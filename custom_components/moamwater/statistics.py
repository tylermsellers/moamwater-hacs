"""Push MyWater daily usage into Home Assistant's long-term statistics.

Mirrors the pattern used by the Spire gas integration (`spire_gas:usage_*`):
an external statistic ID with `has_sum=True`, `mean_type=StatisticMeanType.NONE`,
so it can be added directly as a water source on the Energy dashboard.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from homeassistant.components.recorder import get_instance
from homeassistant.components.recorder.models import (
    StatisticData,
    StatisticMeanType,
    StatisticMetaData,
)
from homeassistant.components.recorder.statistics import (
    async_add_external_statistics,
    get_last_statistics,
    statistics_during_period,
)
from homeassistant.const import UnitOfVolume
from homeassistant.core import HomeAssistant
from homeassistant.util import dt as dt_util

from .const import STATISTIC_ID, STATISTIC_ID_IRRIGATION

_LOGGER = logging.getLogger(__name__)

_DOMAIN_PREFIX = "moamwater"


async def async_import_daily_statistics(hass: HomeAssistant, daily_usage: dict) -> None:
    """Convert a daily usage chart payload into HA external statistics.

    `daily_usage` is the {"categories": [...dates...], "series": {"Actual Usage": [...gallons...]}}
    structure returned by MoAmWaterApiClient.async_get_daily_usage().
    """
    categories = daily_usage.get("categories", [])
    values = daily_usage.get("series", {}).get("Actual Usage", [])
    if not categories or not values:
        _LOGGER.debug("No daily usage data available to import as statistics")
        return

    last_stats = await get_instance(hass).async_add_executor_job(
        get_last_statistics, hass, 1, STATISTIC_ID, True, {"sum"}
    )
    running_sum = 0.0
    last_stats_time: datetime | None = None
    if last_stats and STATISTIC_ID in last_stats:
        last_entry = last_stats[STATISTIC_ID][0]
        running_sum = last_entry.get("sum") or 0.0
        last_stats_time = dt_util.utc_from_timestamp(last_entry["start"])

    statistics: list[StatisticData] = []
    for category, value in zip(categories, values):
        if value is None:
            continue
        try:
            # MyWater daily categories are typically "MM/DD" or ISO date strings;
            # attempt a couple of common formats.
            day = _parse_category_date(category)
        except ValueError:
            _LOGGER.debug("Skipping unparsable date category: %s", category)
            continue

        start = dt_util.as_utc(datetime(day.year, day.month, day.day))
        if last_stats_time is not None and start <= last_stats_time:
            continue

        running_sum += value
        statistics.append(
            StatisticData(start=start, state=value, sum=running_sum)
        )

    if not statistics:
        return

    metadata = StatisticMetaData(
        mean_type=StatisticMeanType.NONE,
        has_sum=True,
        name="MyWater Usage",
        source=_DOMAIN_PREFIX,
        statistic_id=STATISTIC_ID,
        unit_of_measurement=UnitOfVolume.GALLONS,
    )
    async_add_external_statistics(hass, metadata, statistics)


async def async_import_irrigation_statistics(
    hass: HomeAssistant, daily_usage: dict, home_entity_id: str
) -> None:
    """Derive an "irrigation-only" external statistic per day.

    MyWater's daily total covers the whole property (irrigation included);
    `home_entity_id` is a home-only usage sensor (e.g. a Flo/Moen leak
    detector's "today's usage" sensor, which resets to 0 daily so its
    per-day recorder `state` already equals that day's home-only total).
    Irrigation for a given day is estimated as
    ``max(0, mywater_day_total - home_day_total)``, clamped at 0 since small
    negative gaps are just meter-read timing/rounding, not real irrigation.
    """
    categories = daily_usage.get("categories", [])
    values = daily_usage.get("series", {}).get("Actual Usage", [])
    if not categories or not values:
        return

    parsed_days: list[tuple[datetime, float]] = []
    for category, value in zip(categories, values):
        if value is None:
            continue
        try:
            day = _parse_category_date(category)
        except ValueError:
            continue
        parsed_days.append((day, value))

    if not parsed_days:
        return

    parsed_days.sort(key=lambda item: item[0])
    range_start = dt_util.as_utc(
        datetime(parsed_days[0][0].year, parsed_days[0][0].month, parsed_days[0][0].day)
    )
    range_end = dt_util.as_utc(
        datetime(parsed_days[-1][0].year, parsed_days[-1][0].month, parsed_days[-1][0].day)
    ) + timedelta(days=1)

    home_stats = await get_instance(hass).async_add_executor_job(
        statistics_during_period,
        hass,
        range_start,
        range_end,
        {home_entity_id},
        "day",
        None,
        {"state"},
    )
    home_by_date: dict[tuple[int, int, int], float] = {}
    for row in home_stats.get(home_entity_id, []):
        row_start = row["start"]
        row_dt = (
            dt_util.as_local(dt_util.utc_from_timestamp(row_start))
            if isinstance(row_start, (int, float))
            else dt_util.as_local(row_start)
        )
        home_by_date[(row_dt.year, row_dt.month, row_dt.day)] = row.get("state") or 0.0

    last_stats = await get_instance(hass).async_add_executor_job(
        get_last_statistics, hass, 1, STATISTIC_ID_IRRIGATION, True, {"sum"}
    )
    running_sum = 0.0
    last_stats_time: datetime | None = None
    if last_stats and STATISTIC_ID_IRRIGATION in last_stats:
        last_entry = last_stats[STATISTIC_ID_IRRIGATION][0]
        running_sum = last_entry.get("sum") or 0.0
        last_stats_time = dt_util.utc_from_timestamp(last_entry["start"])

    statistics: list[StatisticData] = []
    for day, total_value in parsed_days:
        start = dt_util.as_utc(datetime(day.year, day.month, day.day))
        if last_stats_time is not None and start <= last_stats_time:
            continue
        home_value = home_by_date.get((day.year, day.month, day.day), 0.0)
        irrigation_value = max(0.0, total_value - home_value)
        running_sum += irrigation_value
        statistics.append(StatisticData(start=start, state=irrigation_value, sum=running_sum))

    if not statistics:
        return

    metadata = StatisticMetaData(
        mean_type=StatisticMeanType.NONE,
        has_sum=True,
        name="MyWater Irrigation Estimate",
        source=_DOMAIN_PREFIX,
        statistic_id=STATISTIC_ID_IRRIGATION,
        unit_of_measurement=UnitOfVolume.GALLONS,
    )
    async_add_external_statistics(hass, metadata, statistics)


def parse_category_date(category: str):
    """Public wrapper around `_parse_category_date` for use by sensor.py."""
    return _parse_category_date(category)


def _parse_category_date(category: str):
    """Parse a chart category label into a date, guessing the current year.

    MyWater's daily chart labels have been observed as short month/day strings
    without a year, since the chart only spans ~30-90 days -- both hyphenated
    (e.g. "Jul-21", confirmed from the live portal's 30-day chart) and
    space-separated (e.g. "Jul 21") forms have been seen.
    """
    # Use a naive "now" for comparisons since strptime() without "%Y" always
    # produces a naive datetime -- comparing naive to timezone-aware raises
    # TypeError.
    now = dt_util.now().replace(tzinfo=None)
    for fmt in ("%m/%d/%Y", "%Y-%m-%d", "%b-%d", "%b %d", "%m/%d"):
        try:
            parsed = datetime.strptime(category, fmt)
        except ValueError:
            continue
        if "%Y" not in fmt:
            parsed = parsed.replace(year=now.year)
            # Handle year-boundary charts (e.g. viewing Dec data in January).
            if parsed > now + timedelta(days=1):
                parsed = parsed.replace(year=now.year - 1)
        return parsed
    raise ValueError(f"Unrecognized date format: {category}")

"""Push MyWater daily usage into Home Assistant's long-term statistics.

Mirrors the pattern used by the Spire gas integration (`spire_gas:usage_*`):
an external statistic ID with `has_sum=True`, `has_mean=False`, so it can be
added directly as a water source on the Energy dashboard.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from homeassistant.components.recorder.models import StatisticData, StatisticMetaData
from homeassistant.components.recorder.statistics import (
    async_add_external_statistics,
    get_last_statistics,
)
from homeassistant.const import UnitOfVolume
from homeassistant.core import HomeAssistant
from homeassistant.util import dt as dt_util

from .const import STATISTIC_ID

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

    last_stats = await hass.async_add_executor_job(
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
        has_mean=False,
        has_sum=True,
        name="MyWater Usage",
        source=_DOMAIN_PREFIX,
        statistic_id=STATISTIC_ID,
        unit_of_measurement=UnitOfVolume.GALLONS,
    )
    async_add_external_statistics(hass, metadata, statistics)


def _parse_category_date(category: str):
    """Parse a chart category label into a date, guessing the current year.

    MyWater's daily chart labels have been observed as short month/day strings
    without a year, since the chart only spans ~30-90 days -- both hyphenated
    (e.g. "Jul-21", confirmed from the live portal's 30-day chart) and
    space-separated (e.g. "Jul 21") forms have been seen.
    """
    now = dt_util.now()
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

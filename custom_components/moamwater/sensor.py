"""Sensor platform for Missouri American Water (MyWater)."""

from __future__ import annotations

import logging
from datetime import date, timedelta

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import UnitOfVolume
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util

from . import MoAmWaterConfigEntry
from .const import CONF_BILLING_CYCLE_START_DAY
from .coordinator import MoAmWaterCoordinator
from .statistics import parse_category_date

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: MoAmWaterConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data.coordinator
    async_add_entities(
        [
            MoAmWaterTodayUsageSensor(coordinator),
            MoAmWaterLastHourUsageSensor(coordinator),
            MoAmWaterYesterdayUsageSensor(coordinator),
            MoAmWaterBillingCycleUsageSensor(coordinator, entry),
        ]
    )


class _MoAmWaterBaseSensor(CoordinatorEntity[MoAmWaterCoordinator], SensorEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator: MoAmWaterCoordinator, description: SensorEntityDescription) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{coordinator.entry_id}_{description.key}"
        self._attr_device_info = coordinator.device_info


class MoAmWaterTodayUsageSensor(_MoAmWaterBaseSensor):
    """Sum of today's hourly usage so far (gallons)."""

    def __init__(self, coordinator: MoAmWaterCoordinator) -> None:
        super().__init__(
            coordinator,
            SensorEntityDescription(
                key="today_usage",
                name="Today's Water Usage",
                icon="mdi:water",
                device_class=SensorDeviceClass.WATER,
                state_class=SensorStateClass.TOTAL_INCREASING,
                native_unit_of_measurement=UnitOfVolume.GALLONS,
            ),
        )

    @property
    def native_value(self) -> float | None:
        hourly = (self.coordinator.data or {}).get("hourly", {})
        values = hourly.get("series", {}).get("Actual Usage", [])
        if not values:
            return None
        return round(sum(v for v in values if v is not None), 1)


class MoAmWaterLastHourUsageSensor(_MoAmWaterBaseSensor):
    """Most recent hour's usage (gallons) from the hourly chart."""

    def __init__(self, coordinator: MoAmWaterCoordinator) -> None:
        super().__init__(
            coordinator,
            SensorEntityDescription(
                key="last_hour_usage",
                name="Last Hour Water Usage",
                icon="mdi:water-outline",
                device_class=SensorDeviceClass.WATER,
                state_class=SensorStateClass.MEASUREMENT,
                native_unit_of_measurement=UnitOfVolume.GALLONS,
            ),
        )

    @property
    def native_value(self) -> float | None:
        hourly = (self.coordinator.data or {}).get("hourly", {})
        values = [v for v in hourly.get("series", {}).get("Actual Usage", []) if v is not None]
        if not values:
            return None
        return round(values[-1], 1)


class MoAmWaterYesterdayUsageSensor(_MoAmWaterBaseSensor):
    """Total usage for the most recently completed full day (gallons)."""

    def __init__(self, coordinator: MoAmWaterCoordinator) -> None:
        super().__init__(
            coordinator,
            SensorEntityDescription(
                key="yesterday_usage",
                name="Yesterday's Water Usage",
                icon="mdi:water-check",
                device_class=SensorDeviceClass.WATER,
                state_class=SensorStateClass.TOTAL,
                native_unit_of_measurement=UnitOfVolume.GALLONS,
            ),
        )

    @property
    def native_value(self) -> float | None:
        daily = (self.coordinator.data or {}).get("daily", {})
        values = [v for v in daily.get("series", {}).get("Actual Usage", []) if v is not None]
        if len(values) < 2:
            return None
        # Last entry is typically today's partial reading; the one before it
        # is the last fully completed day.
        return round(values[-2], 1)


def _cycle_start_date(start_day: int, reference: date) -> date:
    """Return the most recent occurrence of `start_day` on/before `reference`."""
    if reference.day >= start_day:
        return reference.replace(day=start_day)
    first_of_month = reference.replace(day=1)
    prev_month_last = first_of_month - timedelta(days=1)
    prev_start_day = min(start_day, prev_month_last.day)
    return prev_month_last.replace(day=prev_start_day)


class MoAmWaterBillingCycleUsageSensor(_MoAmWaterBaseSensor):
    """Cycle-to-date usage total, summed directly from the daily chart data.

    Computed fresh from ``coordinator.data["daily"]`` on every refresh --
    always current and self-correcting (no manual accumulator/reset needed)
    as long as the daily chart data covers back to the cycle's start day.
    Only created if the entry's "billing cycle start day" option is set
    (see `config_flow.py`'s `MoAmWaterOptionsFlow`); otherwise this reports
    unknown/unavailable.
    """

    def __init__(self, coordinator: MoAmWaterCoordinator, entry: MoAmWaterConfigEntry) -> None:
        super().__init__(
            coordinator,
            SensorEntityDescription(
                key="billing_cycle_usage",
                name="Billing Cycle Usage",
                icon="mdi:water-check",
                device_class=SensorDeviceClass.WATER,
                state_class=SensorStateClass.TOTAL_INCREASING,
                native_unit_of_measurement=UnitOfVolume.GALLONS,
            ),
        )
        self._entry = entry

    @property
    def native_value(self) -> float | None:
        start_day = self._entry.options.get(CONF_BILLING_CYCLE_START_DAY)
        if not start_day:
            return None

        daily = (self.coordinator.data or {}).get("daily", {})
        categories = daily.get("categories", [])
        values = daily.get("series", {}).get("Actual Usage", [])
        if not categories or not values:
            return None

        cycle_start = _cycle_start_date(int(start_day), dt_util.now().date())
        total = 0.0
        for category, value in zip(categories, values):
            if value is None:
                continue
            try:
                day = parse_category_date(category)
            except ValueError:
                continue
            if day.date() >= cycle_start:
                total += value
        return round(total, 1)

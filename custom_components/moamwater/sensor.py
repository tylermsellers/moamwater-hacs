"""Sensor platform for Missouri American Water (MyWater)."""

from __future__ import annotations

import logging

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

from . import MoAmWaterConfigEntry
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
                state_class=SensorStateClass.TOTAL,
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
    """Total usage for the most recently completed full day (gallons).

    Also exposes the full daily chart as a generic `daily_history` attribute
    (a list of ``{"date": "YYYY-MM-DD", "gallons": <float>}``, oldest first,
    typically 30-90 days) so any cycle-specific math (e.g. "sum usage since
    the 30th of the month") can be done entirely in your own
    `configuration.yaml` templates -- this integration makes no assumptions
    about your billing cycle.
    """

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

    @property
    def extra_state_attributes(self) -> dict[str, list[dict[str, float | str]]]:
        daily = (self.coordinator.data or {}).get("daily", {})
        categories = daily.get("categories", [])
        values = daily.get("series", {}).get("Actual Usage", [])
        history: list[dict[str, float | str]] = []
        for category, value in zip(categories, values):
            if value is None:
                continue
            try:
                day = parse_category_date(category)
            except ValueError:
                continue
            history.append({"date": day.date().isoformat(), "gallons": round(value, 1)})
        history.sort(key=lambda item: item["date"])
        return {"daily_history": history}

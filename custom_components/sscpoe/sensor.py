from homeassistant.core import HomeAssistant, callback
from homeassistant.const import (
    UnitOfElectricPotential,
    UnitOfPower,
)
from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, LOGGER
from .coordinator import SSCPOE_Coordinator


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: SSCPOE_Coordinator = hass.data[DOMAIN][config_entry.entry_id]
    new_devices = []

    if coordinator.devices:
        for i, sn in enumerate(coordinator.devices):
            device = coordinator.devices[sn]
            ports = len(device["detail"]["pw"])
            reverse = (ports - 1) if coordinator.reverse_order(sn) else 0
            for port in range(ports):
                new_devices.append(
                    PortPowerSensor(
                        coordinator, sn, port+1, (reverse - port) if reverse else port
                    )
                )
            if "tp" in device["detail"]:
                new_devices.append(PortPowerSensor(coordinator, sn, -1, -1))
            if "vol" in device["detail"]:
                new_devices.append(VoltageSensor(coordinator, sn))

    if new_devices:
        async_add_entities(new_devices)


class PortPowerSensor(CoordinatorEntity[SSCPOE_Coordinator], SensorEntity):
    _attr_native_unit_of_measurement = UnitOfPower.WATT
    _attr_device_class = SensorDeviceClass.POWER
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_icon = "mdi:flash"

    def __init__(self, coordinator: SSCPOE_Coordinator, sn: str, port: int, index: int):
        self._sn = sn
        self._index = index
        device = coordinator.devices[sn]
        pid = device["pid"]
        detail = device["detail"]
        prj_name = (
            coordinator.prj[pid]["name"] + "/"
            if pid != SSCPOE_Coordinator.LOCAL_PID
            else ""
        )
        local = "local_" if pid == SSCPOE_Coordinator.LOCAL_PID else ""
        super().__init__(coordinator, context=(pid, sn))
        if index == -1:
            self._attr_name = f"{prj_name}{detail['name']} Total Power"
            self._attr_unique_id = f"{local}{sn}_total_power".lower()
            self.entity_id = f"{DOMAIN}.{local}{sn}_total_power".lower()
        else:
            self._attr_name = f"{prj_name}{detail['name']} Port {port} Power"
            self._attr_unique_id = f"{local}{sn}_{port}_power".lower()
            self.entity_id = f"{DOMAIN}.{local}{sn}_{port}_power".lower()
        self._attr_device_info = device["device_info"]

    @callback
    def _handle_coordinator_update(self) -> None:
        if self._index == -1:
            self._attr_native_value = self.coordinator.devices[self._sn]["detail"]["tp"]
        else:
            self._attr_native_value = self.coordinator.devices[self._sn]["detail"][
                "pw"
            ][self._index]
        self.async_write_ha_state()
        super()._handle_coordinator_update()

    async def async_added_to_hass(self) -> None:
        """When entity is added to hass."""
        await super().async_added_to_hass()
        self._handle_coordinator_update()


class VoltageSensor(CoordinatorEntity[SSCPOE_Coordinator], SensorEntity):
    _attr_native_unit_of_measurement = UnitOfElectricPotential.VOLT
    _attr_device_class = SensorDeviceClass.VOLTAGE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_icon = "mdi:sine-wave"

    def __init__(self, coordinator: SSCPOE_Coordinator, sn: str):
        self._sn = sn
        device = coordinator.devices[sn]
        pid = device["pid"]
        detail = device["detail"]
        prj_name = (
            coordinator.prj[pid]["name"] + "/"
            if pid != SSCPOE_Coordinator.LOCAL_PID
            else ""
        )
        local = "local_" if pid == SSCPOE_Coordinator.LOCAL_PID else ""
        super().__init__(coordinator, context=(pid, sn))
        self._attr_name = f"{prj_name}{detail['name']} Voltage"
        self._attr_unique_id = f"{local}{sn}_voltage".lower()
        self.entity_id = f"{DOMAIN}.{local}{sn}_voltage".lower()
        self._attr_device_info = device["device_info"]

    @callback
    def _handle_coordinator_update(self) -> None:
        self._attr_native_value = self.coordinator.devices[self._sn]["detail"]["vol"]
        self.async_write_ha_state()
        super()._handle_coordinator_update()

    async def async_added_to_hass(self) -> None:
        """When entity is added to hass."""
        await super().async_added_to_hass()
        self._handle_coordinator_update()

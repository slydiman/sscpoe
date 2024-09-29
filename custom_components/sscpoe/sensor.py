from homeassistant.core import HomeAssistant, callback
from homeassistant.const import (
    UnitOfElectricPotential,
    UnitOfPower,
    UnitOfDataRate,
    EntityCategory,
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
            detail = coordinator.devices[sn]["detail"]

            if "vol" in detail:
                new_devices.append(VoltageSensor(coordinator, sn, -1, -1))

            if "tp" in detail:
                new_devices.append(PortPowerSensor(coordinator, sn, -1, -1))

            lans = 0
            if "link" in detail:
                lans = len(detail["link"])
            elif "phyc" in detail:
                lans = len(detail["phyc"])
            elif "rx" in detail:
                lans = len(detail["rx"])
            elif "tx" in detail:
                lans = len(detail["tx"])

            ports = 0
            if "pw" in detail:
                ports = len(detail["pw"])
            elif "poec" in detail:
                ports = len(detail["poec"])

            reverse = (ports - 1) if coordinator.reverse_order(sn) else 0

            if "pw" in detail:
                for port in range(ports):
                    new_devices.append(
                        PortPowerSensor(
                            coordinator,
                            sn,
                            port + 1,
                            (reverse - port) if reverse else port,
                        )
                    )

            for port in range(lans):
                if "link" in detail:
                    new_devices.append(
                        PortLinkSensor(
                            coordinator,
                            sn,
                            port + 1,
                            (reverse - port) if reverse else port,
                        )
                        if port < ports
                        else PortLinkSensor(coordinator, sn, ports - port - 1, port)
                    )
                if "rx" in detail:
                    new_devices.append(
                        PortRxSensor(
                            coordinator,
                            sn,
                            port + 1,
                            (reverse - port) if reverse else port,
                        )
                        if port < ports
                        else PortRxSensor(coordinator, sn, ports - port - 1, port)
                    )
                if "tx" in detail:
                    new_devices.append(
                        PortTxSensor(
                            coordinator,
                            sn,
                            port + 1,
                            (reverse - port) if reverse else port,
                        )
                        if port < ports
                        else PortTxSensor(coordinator, sn, ports - port - 1, port)
                    )

    if new_devices:
        async_add_entities(new_devices)


class PortBaseSensor(CoordinatorEntity[SSCPOE_Coordinator], SensorEntity):
    _desc_name = None
    _id_name = None
    _total_key = None
    _port_key = None
    _total = False

    def __init__(self, coordinator: SSCPOE_Coordinator, sn: str, port: int, index: int):
        self._sn = sn
        self._index = index
        device = coordinator.devices[sn]
        pid = device["pid"]
        super().__init__(coordinator, context=(pid, sn))
        # CoordinatorEntity.__init__(self, coordinator, context=(pid, sn))
        detail = device["detail"]
        prj_name = (
            f"{coordinator.prj[pid]['name']}/{detail['name']} "
            if pid != SSCPOE_Coordinator.LOCAL_PID
            else ""
        )
        cloud = "cloud_" if pid != SSCPOE_Coordinator.LOCAL_PID else ""
        if index < 0:
            Total = "Total " if self._total else ""
            total = "total_" if self._total else ""
            self._attr_name = f"{prj_name}{Total}{self._desc_name}"
            self._attr_unique_id = f"{cloud}{sn}_{total}{self._id_name}".lower()
            self.entity_id = f"{DOMAIN}.{cloud}{sn}_{total}{self._id_name}".lower()
        elif port < 0:
            self._attr_name = f"{prj_name}LAN{-port} {self._desc_name}"
            self._attr_unique_id = f"{cloud}{sn}_lan{-port}_{self._id_name}".lower()
            self.entity_id = f"{DOMAIN}.{cloud}{sn}_lan{-port}_{self._id_name}".lower()
        else:
            self._attr_name = f"{prj_name}Port {port} {self._desc_name}"
            self._attr_unique_id = f"{cloud}{sn}_{port}_{self._id_name}".lower()
            self.entity_id = f"{DOMAIN}.{cloud}{sn}_{port}_{self._id_name}".lower()
        self._attr_device_info = device["device_info"]

    @callback
    def _handle_coordinator_update(self) -> None:
        self._attr_native_value = self._handle_coordinator_update_fix(
            self.coordinator.devices[self._sn]["detail"][self._total_key]
            if self._index < 0
            else self.coordinator.devices[self._sn]["detail"][self._port_key][
                self._index
            ]
        )
        self.async_write_ha_state()
        super()._handle_coordinator_update()

    def _handle_coordinator_update_fix(self, val):
        return val

    def _kb2mb(self, val):
        return ("0." + val) if (isinstance(val, str) and val.find(".") < 0) else val

    async def async_added_to_hass(self) -> None:
        """When entity is added to hass."""
        await super().async_added_to_hass()
        self._handle_coordinator_update()


class VoltageSensor(PortBaseSensor):
    _attr_native_unit_of_measurement = UnitOfElectricPotential.VOLT
    _attr_device_class = SensorDeviceClass.VOLTAGE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_icon = "mdi:sine-wave"

    _desc_name = "Voltage"
    _id_name = "voltage"
    _total_key = "vol"


class PortPowerSensor(PortBaseSensor):
    _attr_native_unit_of_measurement = UnitOfPower.WATT
    _attr_device_class = SensorDeviceClass.POWER
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_icon = "mdi:flash"

    _desc_name = "Power"
    _id_name = "power"
    _total_key = "tp"
    _port_key = "pw"
    _total = True


class PortRxSensor(PortBaseSensor):
    _attr_native_unit_of_measurement = UnitOfDataRate.MEGABITS_PER_SECOND
    _attr_device_class = SensorDeviceClass.DATA_RATE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_entity_registry_enabled_default = False
    _attr_icon = "mdi:transfer-down"

    _desc_name = "RX"
    _id_name = "rx"
    _port_key = "rx"

    def _handle_coordinator_update_fix(self, val):
        return self._kb2mb(val)


class PortTxSensor(PortBaseSensor):
    _attr_native_unit_of_measurement = UnitOfDataRate.MEGABITS_PER_SECOND
    _attr_device_class = SensorDeviceClass.DATA_RATE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_entity_registry_enabled_default = False
    _attr_icon = "mdi:transfer-up"

    _desc_name = "TX"
    _id_name = "tx"
    _port_key = "tx"

    def _handle_coordinator_update_fix(self, val):
        return self._kb2mb(val)


class PortLinkSensor(PortBaseSensor):
    # _attr_native_unit_of_measurement = UnitOfDataRate.MEGABITS_PER_SECOND
    _attr_device_class = SensorDeviceClass.ENUM
    # _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_entity_registry_enabled_default = False
    _attr_icon = "mdi:lan-connect"

    _desc_name = "Link"
    _id_name = "link"
    _port_key = "link"

    def _handle_coordinator_update_fix(self, val):
        match val:
            case 0:
                return "disconnected"
            case 1:
                return f"10M half duplex"
            case 2:
                return f"10M"
            case 3:
                return f"100M half duplex"
            case 4:
                return f"100M"
            case 5:
                return f"1.0G"
            case _:
                return val

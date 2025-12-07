from homeassistant.core import HomeAssistant, callback
from homeassistant.config_entries import ConfigEntry
from homeassistant.components.switch import SwitchEntity
from homeassistant.helpers.entity import EntityCategory
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
        for d, sn in enumerate(coordinator.devices):
            device = coordinator.devices[sn]
            if "poec" in device["detail"]:
                ports = len(device["detail"]["poec"])
                reverse = SSCPOE_Coordinator.reverse_order(sn)
                for i in range(ports):
                    new_devices.append(
                        POEPortSwitch(
                            coordinator,
                            sn,
                            i + 1,
                            (ports - 1 - i) if reverse else i,
                        )
                    )
                if "phyc" in device["detail"]:
                    for i in range(ports):
                        new_devices.append(
                            ExtendPortSwitch(
                                coordinator,
                                sn,
                                i + 1,
                                (ports - 1 - i) if reverse else i,
                            )
                        )

    if new_devices:
        async_add_entities(new_devices)


class POEPortSwitch(CoordinatorEntity[SSCPOE_Coordinator], SwitchEntity):
    def __init__(self, coordinator: SSCPOE_Coordinator, sn: str, port: int, index: int):
        self._sn = sn
        self._index = index
        device = coordinator.devices[sn]
        self._pid = device["pid"]
        detail = device["detail"]
        prj_name = (
            f"{coordinator.prj[self._pid]['name']}/{detail['name']} "
            if SSCPOE_Coordinator.is_cloud(self._pid)
            else ""
        )
        cloud = "cloud_" if SSCPOE_Coordinator.is_cloud(self._pid) else ""
        super().__init__(coordinator, context=(self._pid, sn))
        self._attr_name = f"{prj_name}Port {port} POE"
        self._attr_unique_id = f"{cloud}{sn}_{port}_switch".lower()
        self.entity_id = f"{DOMAIN}.{cloud}{sn}_{port}_switch".lower()
        self._attr_device_info = device["device_info"]

    @property
    def icon(self):
        if self.is_on:
            return "mdi:ethernet"
        else:
            return "mdi:ethernet-off"

    #    @property
    #    def is_on(self) -> bool:
    #        return self.coordinator.devices[self._sn]['detail']['poec'][self._index] != 0

    @callback
    def _handle_coordinator_update(self) -> None:
        self._attr_is_on = (
            self.coordinator.devices[self._sn]["detail"]["poec"][self._index] != 0
        )
        self.async_write_ha_state()
        super()._handle_coordinator_update()

    async def async_added_to_hass(self) -> None:
        """When entity is added to hass."""
        await super().async_added_to_hass()
        self._handle_coordinator_update()

    async def async_turn_on(self, **kwargs):
        """Turn on."""
        await self.coordinator._async_switch_poe(self._pid, self._sn, self._index, True)

        self.coordinator.devices[self._sn]["detail"]["poec"][self._index] = 1
        self.async_write_ha_state()
        await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs) -> None:
        """Turn off."""
        await self.coordinator._async_switch_poe(
            self._pid, self._sn, self._index, False
        )

        self.coordinator.devices[self._sn]["detail"]["poec"][self._index] = 0
        self.async_write_ha_state()
        await self.coordinator.async_request_refresh()


class ExtendPortSwitch(CoordinatorEntity[SSCPOE_Coordinator], SwitchEntity):
    def __init__(self, coordinator: SSCPOE_Coordinator, sn: str, port: int, index: int):
        self._sn = sn
        self._index = index
        device = coordinator.devices[sn]
        self._pid = device["pid"]
        detail = device["detail"]
        prj_name = (
            f"{coordinator.prj[self._pid]['name']}/{detail['name']} "
            if SSCPOE_Coordinator.is_cloud(self._pid)
            else ""
        )
        cloud = "cloud_" if SSCPOE_Coordinator.is_cloud(self._pid) else ""
        super().__init__(coordinator, context=(self._pid, sn))
        self._attr_name = f"{prj_name}Port {port} Extend"
        self._attr_unique_id = f"{cloud}{sn}_{port}_extend_switch".lower()
        self.entity_id = f"{DOMAIN}.{cloud}{sn}_{port}_extend_switch".lower()
        self._attr_device_info = device["device_info"]

    @property
    def icon(self):
        if self.is_on:
            return "mdi:transmission-tower"
        else:
            return "mdi:transmission-tower-off"

    @callback
    def _handle_coordinator_update(self) -> None:
        self._attr_is_on = (
            0 < self.coordinator.devices[self._sn]["detail"]["phyc"][self._index] < 3
        )
        self.async_write_ha_state()
        super()._handle_coordinator_update()

    async def async_added_to_hass(self) -> None:
        """When entity is added to hass."""
        await super().async_added_to_hass()
        self._handle_coordinator_update()

    async def async_turn_on(self, **kwargs):
        """Turn on."""
        await self.coordinator._async_switch_extend(
            self._pid, self._sn, self._index, True
        )

        self.coordinator.devices[self._sn]["detail"]["phyc"][self._index] = 2
        self.async_write_ha_state()
        await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs) -> None:
        """Turn off."""
        await self.coordinator._async_switch_extend(
            self._pid, self._sn, self._index, False
        )

        self.coordinator.devices[self._sn]["detail"]["phyc"][self._index] = 4
        self.async_write_ha_state()
        await self.coordinator.async_request_refresh()

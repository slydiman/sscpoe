from homeassistant.core import HomeAssistant, callback
from homeassistant.config_entries import ConfigEntry
from homeassistant.components.switch import SwitchEntity
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, LOGGER
from . import SSCPOE_Coordinator


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: SSCPOE_Coordinator = hass.data[DOMAIN][config_entry.entry_id]
    new_devices = []

    for i, sn in enumerate(coordinator.devices):
        device = coordinator.devices[sn]
        ports = len(device["detail"]["poec"])
        for port in range(ports):
            new_devices.append(POEPortSwitch(coordinator, sn, port))

    if new_devices:
        async_add_entities(new_devices)


class POEPortSwitch(CoordinatorEntity[SSCPOE_Coordinator], SwitchEntity):
    def __init__(self, coordinator: SSCPOE_Coordinator, sn: str, port: int):
        self._sn = sn
        self._port = port
        device = coordinator.devices[sn]
        self._pid = device["pid"]
        detail = device["detail"]
        prj_name = coordinator.prj[self._pid]["name"]
        super().__init__(coordinator, context=(self._pid, sn))
        self._attr_name = f"{prj_name}/{detail['name']}/port {port+1} POE"
        self._attr_unique_id = f"{sn}_{port+1}_switch".lower()
        self.entity_id = f"{DOMAIN}.{sn}_{port+1}_switch".lower()
        self._attr_device_info = device["device_info"]

    @property
    def icon(self):
        if self.is_on:
            return "mdi:toggle-switch-variant"  # "mdi:ethernet"
        else:
            return "mdi:toggle-switch-variant-off"  # "mdi:ethernet-off"

    #    @property
    #    def is_on(self) -> bool:
    #        return self.coordinator.devices[self._sn]['detail']['poec'][self._port] != 0

    @callback
    def _handle_coordinator_update(self) -> None:
        self._attr_is_on = (
            self.coordinator.devices[self._sn]["detail"]["poec"][self._port] != 0
        )
        self.async_write_ha_state()
        super()._handle_coordinator_update()

    async def async_added_to_hass(self) -> None:
        """When entity is added to hass."""
        await super().async_added_to_hass()
        self._handle_coordinator_update()

    async def async_turn_on(self, **kwargs):
        """Turn on."""
        await self.coordinator._async_switch_poe(self._pid, self._sn, self._port, True)

        self.coordinator.devices[self._sn]["detail"]["poec"][self._port] = 1
        self.async_write_ha_state()
        await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs) -> None:
        """Turn off."""
        await self.coordinator._async_switch_poe(self._pid, self._sn, self._port, False)

        self.coordinator.devices[self._sn]["detail"]["poec"][self._port] = 0
        self.async_write_ha_state()
        await self.coordinator.async_request_refresh()

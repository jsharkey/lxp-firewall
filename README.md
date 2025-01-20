This is a collection of Linux `nftables` firewall rules that perform deep packet inspection to limit the external attack surface of these popular solar hybrid inverters:

* EG4 18kPV-12LV
* EG4 12000XP
* LuxPower LXP-LB-EU 12K

See below for background information and examples of how to deploy these rules.

## OpenWrt Instructions

> [!WARNING]
> These firewall rules prevent remotely modifying any inverter settings from the cloud or app, meaning you’ll need to modify them in-person at the physical inverter LCD, or temporarily lift these rules.  There is a narrow allowance that allows remotely modifying the date/time to adjust for clock drift and applying DST changes.

This assumes you're running an OpenWrt 22.03+ based router, which is after they migrated to an `nftables` based firewall.

1. Gain SSH access to your OpenWrt router.

1. Copy the `10-lxp.nft` file to `/etc/nftables.d/10-lxp.nft` on the router, possibly using a command like this:
> ```
> scp -O ~/Downloads/10-lxp.nft root@192.168.1.1:/etc/nftables.d/10-lxp.nft
> ```

1. Reload your firewall rules using `/etc/init.d/firewall reload` or by rebooting.

1. Block suspicious DNS domains locally using `dnsmasq` rules in `/etc/config/dhcp`, or adding them to a NextDNS denylist:
> ```
>    list server '/.fogcloud.io/'
> ```

1. Reload your DNS rules using `/etc/init.d/dnsmasq reload` or by rebooting.

## Background

I’ve been working with an EG4 18kPV-12LV hybrid inverter, and was curious about how its cloud monitoring system was designed.  To my surprise, there is **no encryption whatsoever**, and raw RS485 MODBUS commands are being sent directly across the public internet. 😲

This means a MITM attacker has trivial control over sensitive inverter parameters, such as battery thresholds and grid-interactive features.  As just one example, the parameters used for IEEE 1547 interaction could be misconfigured as part of a larger effort to destabilize the grid.  Finally, the entire inverter firmware appears to be updatable via this route, possibly opening up an even wider attack surface area beyond just the documented MODBUS parameters. 😲

There were [recent rumors of solar inverters being attacked remotely](https://today.lorientlejour.com/article/1427662/did-solar-power-energy-systems-explode-during-wednesdays-attack.html), but they appear to have been dispelled after investigators followed-up.  Regardless, it remains prudent to reduce the external attack surface of these devices, as they are often connected to potent energy storage systems.

One way to mitigate this would be to completely disconnect the inverter from the Internet, but that would mean having to roll our own local monitoring.  [Efforts have been made by others to build this out](https://github.com/celsworth/lxp-bridge), but they require additional local hardware and can be complex to configure and manage.

## Firewall-style Approach

As an alternative, we can use the raw plaintext protocol to our advantage and write a handful of deep packet inspection (DPI) firewall rules that allow a handful of vetted innocent requests through, while blocking all other mutation requests or otherwise undocumented features.  This lets us leverage the existing cloud monitoring infrastructure and inverter as-is with no extra hardware requirements.

Additionally, there are some suspicious DNS requests emanating hourly from the MiCO IoTOS for `mac.fogcloud.io` and `alimac.fogcloud.io`.  They don't currently resolve, which means if they become active in the future they could unlock dormant behavior, so they should be blocked using using local `dnsmasq` rules or a NextDNS denylist.

## Testing

Using extensive local packet captures I wrote `tests.py` to confirm that the `nftables` rules are allowing or blocking commonly observed packet flows.

When attempting to modify settings in the cloud or app I now get "Timeout" or "Unknown error" messages, and then it takes a few minutes for RS485 tunnel to be reestablished and automatic statistics to begin flowing again.

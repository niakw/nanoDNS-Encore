# Credits and provenance


**Language:** English (default) | [Français](CREDITS.fr.md)
## Original nanoDNS source

The C payload was authored by [Drakmor](https://github.com/drakmor/nanoDNS) and distributed under the GNU GPL-3.0 license. This fork preserves the upstream copyright notices and [license](../LICENSE). Original upstream repository and release notes: https://github.com/drakmor/nanoDNS .

## DNS policy

The mandatory 124-rule configuration and categorized console/publisher hostname research are from [niakw/nanodns-console-blocklist](https://github.com/niakw/nanodns-console-blocklist), version 3 profile. Its [source bibliography](https://github.com/niakw/nanodns-console-blocklist/blob/main/docs/SOURCES.md) credits other independent community work, including Al-Azif, MagicStuffCL, cjrb007, Misl3d and ZixX3r.

The rule snapshot is used in both `nanodns.ini` and the native protected-mask array; their exact parity is enforced by automated tests. Changes should be reviewed alongside the source policy, never silently updated over the network.

## DNS upstream

Default resolvers: [Control D](https://docs.controld.com/docs/free-dns) (unfiltered) and [AdGuard DNS](https://adguard-dns.io/en/public-dns.html) (non-filtering). Neither provider maintains this project. Quad9 was used in earlier releases.

## Integration

This firmware-13.60-focused integration is maintained in [niakw/nanoDNS-Encore](https://github.com/niakw/nanoDNS-Encore). It is not an official Drakmor release and has no platform vendor, additional console networks or platform operator affiliation.

The fork does not add third-party proprietary assets. Source and modifications remain subject to [GPL-3.0](../LICENSE).

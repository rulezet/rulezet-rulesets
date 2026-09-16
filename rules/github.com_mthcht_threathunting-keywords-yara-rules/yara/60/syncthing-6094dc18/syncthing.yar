rule syncthing
{
    meta:
        description = "Detection patterns for the tool 'syncthing' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "syncthing"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "/bin/syncthing"
                        $string2 = /\/syncthing\.exe/ nocase ascii wide
                        $string3 = "/syncthing/releases/latest" nocase ascii wide
                        $string4 = "/syncthing-linux-"
                        $string5 = /\\syncthing\.exe/ nocase ascii wide
                        $string6 = ">Syncthing<" nocase ascii wide
                        $string7 = "1cc0257d93b4d1c0b3c923c923c2997f222d271591addbdd2da0da019dbb5fe579" nocase ascii wide
                        $string8 = "48adf2450c4a087c1c4982a2a789d8f1b1e88b8b8d959fb273a76f8b1888" nocase ascii wide
                        $string9 = "4d3c48917973daaf7e31aeab167e4611c60feed29bae25303c053824bef027c" nocase ascii wide
                        $string10 = "bf895dca1ea67bf39a6bd87168af8d4fd6321d2f2d071295dbd4d25508eb68" nocase ascii wide
                        $string11 = /crash\.syncthing\.net/ nocase ascii wide
                        $string12 = /data\.syncthing\.net/ nocase ascii wide
                        $string13 = /http\:\/\/127\.0\.0\.1\:8384/ nocase ascii wide
                        $string14 = /par\-k8s\.syncthing\.net/ nocase ascii wide
                        $string15 = /par\-k8s\-v4\.syncthing\.net/ nocase ascii wide
                        $string16 = /relays\.syncthing\.net/ nocase ascii wide
                        $string17 = /stun\.syncthing\.net/ nocase ascii wide
                        $string18 = /SyncthingFirewallRule\.js/ nocase ascii wide
                        $string19 = /SyncthingLogonTask\.js/ nocase ascii wide
                        $string20 = /syncthing\-windows\-setup\.exe/ nocase ascii wide
                        $string21 = /upgrades\.syncthing\.net/ nocase ascii wide

    condition:
        any of them
}
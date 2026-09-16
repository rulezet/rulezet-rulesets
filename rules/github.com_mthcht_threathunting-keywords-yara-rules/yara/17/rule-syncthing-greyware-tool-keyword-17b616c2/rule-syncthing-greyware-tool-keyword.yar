rule rule_syncthing_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'syncthing' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "syncthing"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_syncthing_greyware_tool_keyword = "/bin/syncthing"
                        $string2_syncthing_greyware_tool_keyword = /\/syncthing\.exe/ nocase ascii wide
                        $string3_syncthing_greyware_tool_keyword = "/syncthing/releases/latest" nocase ascii wide
                        $string4_syncthing_greyware_tool_keyword = "/syncthing-linux-"
                        $string5_syncthing_greyware_tool_keyword = /\\syncthing\.exe/ nocase ascii wide
                        $string6_syncthing_greyware_tool_keyword = ">Syncthing<" nocase ascii wide
                        $string7_syncthing_greyware_tool_keyword = "1cc0257d93b4d1c0b3c923c923c2997f222d271591addbdd2da0da019dbb5fe579" nocase ascii wide
                        $string8_syncthing_greyware_tool_keyword = "48adf2450c4a087c1c4982a2a789d8f1b1e88b8b8d959fb273a76f8b1888" nocase ascii wide
                        $string9_syncthing_greyware_tool_keyword = "4d3c48917973daaf7e31aeab167e4611c60feed29bae25303c053824bef027c" nocase ascii wide
                        $string10_syncthing_greyware_tool_keyword = "bf895dca1ea67bf39a6bd87168af8d4fd6321d2f2d071295dbd4d25508eb68" nocase ascii wide
                        $string11_syncthing_greyware_tool_keyword = /crash\.syncthing\.net/ nocase ascii wide
                        $string12_syncthing_greyware_tool_keyword = /data\.syncthing\.net/ nocase ascii wide
                        $string13_syncthing_greyware_tool_keyword = /http\:\/\/127\.0\.0\.1\:8384/ nocase ascii wide
                        $string14_syncthing_greyware_tool_keyword = /par\-k8s\.syncthing\.net/ nocase ascii wide
                        $string15_syncthing_greyware_tool_keyword = /par\-k8s\-v4\.syncthing\.net/ nocase ascii wide
                        $string16_syncthing_greyware_tool_keyword = /relays\.syncthing\.net/ nocase ascii wide
                        $string17_syncthing_greyware_tool_keyword = /stun\.syncthing\.net/ nocase ascii wide
                        $string18_syncthing_greyware_tool_keyword = /SyncthingFirewallRule\.js/ nocase ascii wide
                        $string19_syncthing_greyware_tool_keyword = /SyncthingLogonTask\.js/ nocase ascii wide
                        $string20_syncthing_greyware_tool_keyword = /syncthing\-windows\-setup\.exe/ nocase ascii wide
                        $string21_syncthing_greyware_tool_keyword = /upgrades\.syncthing\.net/ nocase ascii wide

    condition:
        any of them
}
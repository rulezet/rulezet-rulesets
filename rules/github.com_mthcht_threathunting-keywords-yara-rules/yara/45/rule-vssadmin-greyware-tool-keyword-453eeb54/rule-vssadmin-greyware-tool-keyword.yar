rule rule_vssadmin_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'vssadmin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vssadmin"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_vssadmin_greyware_tool_keyword = /\.exe\sdelete\sshadows/ nocase ascii wide
                        $string2_vssadmin_greyware_tool_keyword = "vssadmin create shadow /for=C:" nocase ascii wide
                        $string3_vssadmin_greyware_tool_keyword = /vssadmin\screate\sshadow\s\/for\=C\:.{0,1000}\s\\Temp\\.{0,1000}\.tmp/ nocase ascii wide
                        $string4_vssadmin_greyware_tool_keyword = "vssadmin delete shadows /all /quiet" nocase ascii wide
                        $string5_vssadmin_greyware_tool_keyword = "vssadmin delete shadows" nocase ascii wide
                        $string6_vssadmin_greyware_tool_keyword = "vssadmin list shadows" nocase ascii wide
                        $string7_vssadmin_greyware_tool_keyword = /vssadmin.{0,1000}\sDelete\sShadows\s\/All\s\/Quiet/ nocase ascii wide
                        $string8_vssadmin_greyware_tool_keyword = /vssadmin.{0,1000}resize\sshadowstorage\s\/for\=c\:\s\/on\=c\:\s\/maxsize\=1/ nocase ascii wide
                        $string9_vssadmin_greyware_tool_keyword = /vssadmin\.exe\sCreate\sShadow\s\/for\=/ nocase ascii wide

    condition:
        any of them
}
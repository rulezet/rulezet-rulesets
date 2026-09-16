rule vssadmin
{
    meta:
        description = "Detection patterns for the tool 'vssadmin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vssadmin"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\.exe\sdelete\sshadows/ nocase ascii wide
                        $string2 = "vssadmin create shadow /for=C:" nocase ascii wide
                        $string3 = /vssadmin\screate\sshadow\s\/for\=C\:.{0,1000}\s\\Temp\\.{0,1000}\.tmp/ nocase ascii wide
                        $string4 = "vssadmin delete shadows /all /quiet" nocase ascii wide
                        $string5 = "vssadmin delete shadows" nocase ascii wide
                        $string6 = "vssadmin list shadows" nocase ascii wide
                        $string7 = /vssadmin.{0,1000}\sDelete\sShadows\s\/All\s\/Quiet/ nocase ascii wide
                        $string8 = /vssadmin.{0,1000}resize\sshadowstorage\s\/for\=c\:\s\/on\=c\:\s\/maxsize\=1/ nocase ascii wide
                        $string9 = /vssadmin\.exe\sCreate\sShadow\s\/for\=/ nocase ascii wide

    condition:
        any of them
}
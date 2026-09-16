rule mssqlproxy
{
    meta:
        description = "Detection patterns for the tool 'mssqlproxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mssqlproxy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/mssqlproxy\.git/ nocase ascii wide
                        $string2 = "blackarrowsec/mssqlproxy" nocase ascii wide
                        $string3 = "mssqlproxy-master" nocase ascii wide
                        $string4 = /reciclador\.cpp/ nocase ascii wide
                        $string5 = /reciclador\.dll/ nocase ascii wide
                        $string6 = /reciclador\.vcxproj/ nocase ascii wide

    condition:
        any of them
}
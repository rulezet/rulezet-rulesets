rule rule_mssqlproxy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'mssqlproxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mssqlproxy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_mssqlproxy_offensive_tool_keyword = /\/mssqlproxy\.git/ nocase ascii wide
                        $string2_mssqlproxy_offensive_tool_keyword = "blackarrowsec/mssqlproxy" nocase ascii wide
                        $string3_mssqlproxy_offensive_tool_keyword = "mssqlproxy-master" nocase ascii wide
                        $string4_mssqlproxy_offensive_tool_keyword = /reciclador\.cpp/ nocase ascii wide
                        $string5_mssqlproxy_offensive_tool_keyword = /reciclador\.dll/ nocase ascii wide
                        $string6_mssqlproxy_offensive_tool_keyword = /reciclador\.vcxproj/ nocase ascii wide

    condition:
        any of them
}
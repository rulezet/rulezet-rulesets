rule rule_pysoxy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pysoxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pysoxy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_pysoxy_offensive_tool_keyword = /\/pysoxy\.git/ nocase ascii wide
                        $string2_pysoxy_offensive_tool_keyword = /\/pysoxy\.py/ nocase ascii wide
                        $string3_pysoxy_offensive_tool_keyword = /\\pysoxy\.py/ nocase ascii wide
                        $string4_pysoxy_offensive_tool_keyword = "MisterDaneel/pysoxy" nocase ascii wide
                        $string5_pysoxy_offensive_tool_keyword = "pysoxy-master" nocase ascii wide

    condition:
        any of them
}
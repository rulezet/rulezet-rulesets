rule rule_privexchange_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'privexchange' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "privexchange"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_privexchange_offensive_tool_keyword = /\/PrivExchange\.git/ nocase ascii wide
                        $string2_privexchange_offensive_tool_keyword = "dirkjanm/PrivExchange" nocase ascii wide
                        $string3_privexchange_offensive_tool_keyword = /httpattack\.py/ nocase ascii wide
                        $string4_privexchange_offensive_tool_keyword = /privexchange\.py/ nocase ascii wide
                        $string5_privexchange_offensive_tool_keyword = /PrivExchange\-master\.zip/ nocase ascii wide

    condition:
        any of them
}
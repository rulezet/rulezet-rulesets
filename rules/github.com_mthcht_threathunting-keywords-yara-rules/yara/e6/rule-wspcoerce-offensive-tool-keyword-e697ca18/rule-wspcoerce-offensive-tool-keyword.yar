rule rule_WSPCoerce_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WSPCoerce' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WSPCoerce"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WSPCoerce_offensive_tool_keyword = /\sWSPCoerce\.cs/ nocase ascii wide
                        $string2_WSPCoerce_offensive_tool_keyword = /\/WSPCoerce\.git/
                        $string3_WSPCoerce_offensive_tool_keyword = /\\WSPCoerce\.cs/ nocase ascii wide
                        $string4_WSPCoerce_offensive_tool_keyword = "slemire/WSPCoerce" nocase ascii wide
                        $string5_WSPCoerce_offensive_tool_keyword = /WSPCoerce\.ex/ nocase ascii wide
                        $string6_WSPCoerce_offensive_tool_keyword = "WSPCoerce-main" nocase ascii wide

    condition:
        any of them
}
rule rule_LAZYPARIAH_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LAZYPARIAH' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LAZYPARIAH"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_LAZYPARIAH_offensive_tool_keyword = " lazypariah" nocase ascii wide
                        $string2_LAZYPARIAH_offensive_tool_keyword = "lazypariah " nocase ascii wide
                        $string3_LAZYPARIAH_offensive_tool_keyword = /lazypariah\.svg/ nocase ascii wide
                        $string4_LAZYPARIAH_offensive_tool_keyword = "octetsplicer/LAZYPARIAH" nocase ascii wide

    condition:
        any of them
}
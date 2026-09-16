rule rule_tir_blanc_holiseum_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tir_blanc_holiseum' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tir_blanc_holiseum"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_tir_blanc_holiseum_greyware_tool_keyword = /\\tir_blanc_holiseum\\.{0,1000}\.exe/ nocase ascii wide
                        $string2_tir_blanc_holiseum_greyware_tool_keyword = /kindloader\.exe.{0,1000}\s\-\-extract\skindlocker/ nocase ascii wide

    condition:
        any of them
}
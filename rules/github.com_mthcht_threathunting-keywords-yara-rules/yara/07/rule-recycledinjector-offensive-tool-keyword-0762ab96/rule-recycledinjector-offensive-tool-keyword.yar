rule rule_RecycledInjector_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RecycledInjector' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RecycledInjector"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RecycledInjector_offensive_tool_keyword = "/RecycledInjector" nocase ascii wide
                        $string2_RecycledInjector_offensive_tool_keyword = /\/RecycledInjector\.git/ nocase ascii wide
                        $string3_RecycledInjector_offensive_tool_keyword = /\/src\/RecycledGate\.h/ nocase ascii wide
                        $string4_RecycledInjector_offensive_tool_keyword = /\\RecycledGate\.c/ nocase ascii wide
                        $string5_RecycledInjector_offensive_tool_keyword = /GateTrampolin\.asm/ nocase ascii wide
                        $string6_RecycledInjector_offensive_tool_keyword = /poc\.exe.{0,1000}poc\.txt/ nocase ascii wide
                        $string7_RecycledInjector_offensive_tool_keyword = /RecycledInjector\.exe/ nocase ascii wide
                        $string8_RecycledInjector_offensive_tool_keyword = "RecycledInjector-main" nocase ascii wide
                        $string9_RecycledInjector_offensive_tool_keyword = "RecycledInjector-main" nocase ascii wide

    condition:
        any of them
}
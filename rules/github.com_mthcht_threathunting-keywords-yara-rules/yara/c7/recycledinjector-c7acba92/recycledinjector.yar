rule RecycledInjector
{
    meta:
        description = "Detection patterns for the tool 'RecycledInjector' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RecycledInjector"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/RecycledInjector" nocase ascii wide
                        $string2 = /\/RecycledInjector\.git/ nocase ascii wide
                        $string3 = /\/src\/RecycledGate\.h/ nocase ascii wide
                        $string4 = /\\RecycledGate\.c/ nocase ascii wide
                        $string5 = /GateTrampolin\.asm/ nocase ascii wide
                        $string6 = /poc\.exe.{0,1000}poc\.txt/ nocase ascii wide
                        $string7 = /RecycledInjector\.exe/ nocase ascii wide
                        $string8 = "RecycledInjector-main" nocase ascii wide
                        $string9 = "RecycledInjector-main" nocase ascii wide

    condition:
        any of them
}
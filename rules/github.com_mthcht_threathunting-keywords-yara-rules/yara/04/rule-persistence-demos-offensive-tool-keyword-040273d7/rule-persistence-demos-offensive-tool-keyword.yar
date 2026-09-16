rule rule_persistence_demos_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'persistence_demos' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "persistence_demos"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_persistence_demos_offensive_tool_keyword = /\/persistence_demos\.git/ nocase ascii wide
                        $string2_persistence_demos_offensive_tool_keyword = /\:\\ProgramData\\demo\.dll/ nocase ascii wide
                        $string3_persistence_demos_offensive_tool_keyword = /\[\-\]\sCOM\sHijacking\sfailed\!/ nocase ascii wide
                        $string4_persistence_demos_offensive_tool_keyword = /\[\-\]\sDropping\sDLL\sfailed\!/ nocase ascii wide
                        $string5_persistence_demos_offensive_tool_keyword = /\[\-\]\sHijacking\sfailed\!/ nocase ascii wide
                        $string6_persistence_demos_offensive_tool_keyword = /\[\+\]\sCOM\sHijacked\!/ nocase ascii wide
                        $string7_persistence_demos_offensive_tool_keyword = /\[\+\]\sDLL\sdropped\!/ nocase ascii wide
                        $string8_persistence_demos_offensive_tool_keyword = /\\ext_hijacker\.h/ nocase ascii wide
                        $string9_persistence_demos_offensive_tool_keyword = /\\hijacker_app\\src\\ProxyApp\.exe/ nocase ascii wide
                        $string10_persistence_demos_offensive_tool_keyword = /\\persistence_demos\-master/ nocase ascii wide
                        $string11_persistence_demos_offensive_tool_keyword = "hasherezade/persistence_demos" nocase ascii wide
                        $string12_persistence_demos_offensive_tool_keyword = "Hello, you have been pwned!" nocase ascii wide

    condition:
        any of them
}
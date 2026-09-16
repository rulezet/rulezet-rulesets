rule persistence_demos
{
    meta:
        description = "Detection patterns for the tool 'persistence_demos' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "persistence_demos"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/persistence_demos\.git/ nocase ascii wide
                        $string2 = /\:\\ProgramData\\demo\.dll/ nocase ascii wide
                        $string3 = /\[\-\]\sCOM\sHijacking\sfailed\!/ nocase ascii wide
                        $string4 = /\[\-\]\sDropping\sDLL\sfailed\!/ nocase ascii wide
                        $string5 = /\[\-\]\sHijacking\sfailed\!/ nocase ascii wide
                        $string6 = /\[\+\]\sCOM\sHijacked\!/ nocase ascii wide
                        $string7 = /\[\+\]\sDLL\sdropped\!/ nocase ascii wide
                        $string8 = /\\ext_hijacker\.h/ nocase ascii wide
                        $string9 = /\\hijacker_app\\src\\ProxyApp\.exe/ nocase ascii wide
                        $string10 = /\\persistence_demos\-master/ nocase ascii wide
                        $string11 = "hasherezade/persistence_demos" nocase ascii wide
                        $string12 = "Hello, you have been pwned!" nocase ascii wide

    condition:
        any of them
}
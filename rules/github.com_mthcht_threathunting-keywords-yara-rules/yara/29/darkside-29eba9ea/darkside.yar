rule Darkside
{
    meta:
        description = "Detection patterns for the tool 'Darkside' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Darkside"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Darkside\.exe/ nocase ascii wide
                        $string2 = /\/Darkside\.git/ nocase ascii wide
                        $string3 = /\/Darkside\.sln/ nocase ascii wide
                        $string4 = /\\Darkside\.exe/ nocase ascii wide
                        $string5 = /\\Darkside\.sln/ nocase ascii wide
                        $string6 = "D90EFC93-2F8B-4427-B967-0E78ED45611E" nocase ascii wide
                        $string7 = /Darkside\.exe\s\-p/ nocase ascii wide
                        $string8 = /Darkside\-master\.zip/ nocase ascii wide
                        $string9 = "ph4nt0mbyt3/Darkside" nocase ascii wide

    condition:
        any of them
}
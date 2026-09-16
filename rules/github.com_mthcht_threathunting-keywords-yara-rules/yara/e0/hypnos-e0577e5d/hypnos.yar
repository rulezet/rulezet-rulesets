rule Hypnos
{
    meta:
        description = "Detection patterns for the tool 'Hypnos' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hypnos"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Hypnos\.git/ nocase ascii wide
                        $string2 = /\\Hypnos\.exe/ nocase ascii wide
                        $string3 = /\\Hypnos\.sln/ nocase ascii wide
                        $string4 = /\\Hypnos\.vcxproj/ nocase ascii wide
                        $string5 = /\\Hypnos\-main\\/ nocase ascii wide
                        $string6 = "CaptainNox/Hypnos" nocase ascii wide
                        $string7 = "D210570B-F1A0-4B66-9301-F7A54978C178" nocase ascii wide
                        $string8 = /Hypnos\-main\.zip/ nocase ascii wide

    condition:
        any of them
}
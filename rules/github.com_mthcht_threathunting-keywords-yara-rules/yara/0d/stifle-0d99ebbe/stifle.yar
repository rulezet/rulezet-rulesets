rule Stifle
{
    meta:
        description = "Detection patterns for the tool 'Stifle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Stifle"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\\tStifle\.exe/ nocase ascii wide
                        $string2 = "186789b7b7c4973d4f941582a796c3ced5ae7fbc4527cf19040e740d380c4106" nocase ascii wide
                        $string3 = "a507307a4b6e0f6f00e8a3f3330204c124fa5a69cfc03ffd89235c7e4b77f25d" nocase ascii wide
                        $string4 = "EDBAAABC-1214-41C0-8EEE-B61056DE37ED" nocase ascii wide
                        $string5 = "logangoins/Stifle" nocase ascii wide
                        $string6 = /Stifle\.exe\sadd\s\/object\:/ nocase ascii wide
                        $string7 = /Stifle\.exe\sclear\s/ nocase ascii wide

    condition:
        any of them
}
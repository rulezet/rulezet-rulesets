rule ShimDB
{
    meta:
        description = "Detection patterns for the tool 'ShimDB' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShimDB"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/sdb\-explorer\.exe/ nocase ascii wide
                        $string2 = /\/ShimDB\.git/ nocase ascii wide
                        $string3 = /\\sdb\-explorer\.exe/ nocase ascii wide
                        $string4 = /\\sdb\-explorer\.sln/ nocase ascii wide
                        $string5 = /\\ShimDB\\sdb\-explorer/ nocase ascii wide
                        $string6 = "223279bb628165de88609c81444f4a9bf9aac6f921ea155ac427a47d13b49084" nocase ascii wide
                        $string7 = "A1A949A4-5CE4-4FCF-A3B9-A2290EA46086" nocase ascii wide
                        $string8 = "jackson5sec/ShimDB" nocase ascii wide

    condition:
        any of them
}
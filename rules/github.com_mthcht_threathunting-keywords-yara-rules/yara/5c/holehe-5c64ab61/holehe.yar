rule holehe
{
    meta:
        description = "Detection patterns for the tool 'holehe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "holehe"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " install holehe"
                        $string2 = /\/holehe\.git/
                        $string3 = /from\sholehe\.core\simport/
                        $string4 = /holehe\s.{0,1000}\@gmail\.com/
                        $string5 = /holehe\.core\:main/
                        $string6 = /holehe\\holehe/
                        $string7 = /holehe\-master\./
                        $string8 = "megadose/holehe"
                        $string9 = /megadose\@protonmail\.com/ nocase ascii wide
                        $string10 = /pornhub\.py/

    condition:
        any of them
}
rule pywsus
{
    meta:
        description = "Detection patterns for the tool 'pywsus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pywsus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-c\s\'\/accepteula\s\/s\scalc\.exe\'\s\-e\sPsExec64\.exe/ nocase ascii wide
                        $string2 = /\/pywsus\.git/ nocase ascii wide
                        $string3 = /\/pywsus\-master\.zip/ nocase ascii wide
                        $string4 = /pywsus\.py/ nocase ascii wide

    condition:
        any of them
}
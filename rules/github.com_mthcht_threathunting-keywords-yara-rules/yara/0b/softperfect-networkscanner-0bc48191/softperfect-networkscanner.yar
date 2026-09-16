rule softperfect_networkscanner
{
    meta:
        description = "Detection patterns for the tool 'softperfect networkscanner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "softperfect networkscanner"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /\sWin64\/NetTool\.SoftPerfectNetscan/ nocase ascii wide
                        $string2 = /Hacktool\.SoftPerfectNetscan/ nocase ascii wide

    condition:
        any of them
}
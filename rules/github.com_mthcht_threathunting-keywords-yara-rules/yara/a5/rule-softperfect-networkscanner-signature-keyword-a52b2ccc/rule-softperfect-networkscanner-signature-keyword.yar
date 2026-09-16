rule rule_softperfect_networkscanner_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'softperfect networkscanner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "softperfect networkscanner"
        rule_category = "signature_keyword"

    strings:
                        $string1_softperfect_networkscanner_signature_keyword = /\sWin64\/NetTool\.SoftPerfectNetscan/ nocase ascii wide
                        $string2_softperfect_networkscanner_signature_keyword = /Hacktool\.SoftPerfectNetscan/ nocase ascii wide

    condition:
        any of them
}
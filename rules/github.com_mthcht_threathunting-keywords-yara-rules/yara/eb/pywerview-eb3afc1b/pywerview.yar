rule pywerview
{
    meta:
        description = "Detection patterns for the tool 'pywerview' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pywerview"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/pywerview" nocase ascii wide
                        $string2 = "invoke-checklocaladminaccess" nocase ascii wide
                        $string3 = "invoke-eventhunter" nocase ascii wide
                        $string4 = "invoke-processhunter" nocase ascii wide
                        $string5 = "invoke-userhunter" nocase ascii wide
                        $string6 = /pywerview\.py/ nocase ascii wide

    condition:
        any of them
}
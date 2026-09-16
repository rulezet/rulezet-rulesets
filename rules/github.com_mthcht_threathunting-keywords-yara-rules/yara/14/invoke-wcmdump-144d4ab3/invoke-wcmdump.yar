rule Invoke_WCMDump
{
    meta:
        description = "Detection patterns for the tool 'Invoke-WCMDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-WCMDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "5a0976fef89e32ddcf62c790f9bb4c174a79004e627c3521604f46bf5cc7bea2" nocase ascii wide
                        $string2 = "Invoke-WCMDump" nocase ascii wide

    condition:
        any of them
}
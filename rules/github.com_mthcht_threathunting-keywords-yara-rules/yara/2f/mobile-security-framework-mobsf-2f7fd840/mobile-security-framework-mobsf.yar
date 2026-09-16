rule Mobile_Security_Framework_MobSF
{
    meta:
        description = "Detection patterns for the tool 'Mobile-Security-Framework-MobSF' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Mobile-Security-Framework-MobSF"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "Framework-MobSF" nocase ascii wide
                        $string2 = "Mobile-Security-Framework" nocase ascii wide

    condition:
        any of them
}
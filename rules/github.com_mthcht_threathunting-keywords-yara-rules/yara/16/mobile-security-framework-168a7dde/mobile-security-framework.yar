rule Mobile_Security_Framework
{
    meta:
        description = "Detection patterns for the tool 'Mobile-Security-Framework' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Mobile-Security-Framework"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "Mobile-Security-Framework" nocase ascii wide

    condition:
        any of them
}
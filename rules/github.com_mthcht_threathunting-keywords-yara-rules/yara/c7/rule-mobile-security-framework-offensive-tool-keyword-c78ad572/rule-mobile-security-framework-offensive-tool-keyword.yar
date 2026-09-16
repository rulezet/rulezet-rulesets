rule rule_Mobile_Security_Framework_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Mobile-Security-Framework' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Mobile-Security-Framework"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Mobile_Security_Framework_offensive_tool_keyword = "Mobile-Security-Framework" nocase ascii wide

    condition:
        any of them
}
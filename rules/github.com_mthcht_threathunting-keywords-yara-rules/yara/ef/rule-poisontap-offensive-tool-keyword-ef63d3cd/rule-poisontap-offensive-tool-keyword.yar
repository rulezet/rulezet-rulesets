rule rule_poisontap_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'poisontap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "poisontap"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_poisontap_offensive_tool_keyword = "poisontap" nocase ascii wide

    condition:
        any of them
}
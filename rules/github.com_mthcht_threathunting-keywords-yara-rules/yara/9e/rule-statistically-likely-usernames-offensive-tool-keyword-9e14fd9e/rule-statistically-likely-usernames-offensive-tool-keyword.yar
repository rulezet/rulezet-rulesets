rule rule_statistically_likely_usernames_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'statistically-likely-usernames' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "statistically-likely-usernames"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_statistically_likely_usernames_offensive_tool_keyword = "statistically-likely-usernames" nocase ascii wide

    condition:
        any of them
}
rule statistically_likely_usernames
{
    meta:
        description = "Detection patterns for the tool 'statistically-likely-usernames' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "statistically-likely-usernames"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "statistically-likely-usernames" nocase ascii wide

    condition:
        any of them
}
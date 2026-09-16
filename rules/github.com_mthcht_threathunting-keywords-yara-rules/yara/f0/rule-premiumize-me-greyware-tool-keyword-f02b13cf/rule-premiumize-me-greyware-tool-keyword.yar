rule rule_premiumize_me_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'premiumize.me' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "premiumize.me"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_premiumize_me_greyware_tool_keyword = /https\:\/\/www\.premiumize\.me\// nocase ascii wide

    condition:
        any of them
}
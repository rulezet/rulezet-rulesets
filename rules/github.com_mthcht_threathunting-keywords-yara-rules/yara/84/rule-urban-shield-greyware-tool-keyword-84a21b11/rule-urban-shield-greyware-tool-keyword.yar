rule rule_Urban_Shield_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Urban Shield' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Urban Shield"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Urban_Shield_greyware_tool_keyword = "almalgbpmcfpdaopimbdchdliminoign" nocase ascii wide

    condition:
        any of them
}
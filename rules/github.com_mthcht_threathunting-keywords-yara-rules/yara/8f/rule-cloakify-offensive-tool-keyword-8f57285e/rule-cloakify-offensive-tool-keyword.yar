rule rule_cloakify_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'cloakify' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cloakify"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_cloakify_offensive_tool_keyword = "cloakify" nocase ascii wide

    condition:
        any of them
}
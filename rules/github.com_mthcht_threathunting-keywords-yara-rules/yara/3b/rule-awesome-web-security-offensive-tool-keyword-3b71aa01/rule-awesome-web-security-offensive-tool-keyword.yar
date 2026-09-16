rule rule_awesome_web_security_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'awesome-web-security' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "awesome-web-security"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_awesome_web_security_offensive_tool_keyword = "awesome-web-security" nocase ascii wide

    condition:
        any of them
}
rule awesome_web_security
{
    meta:
        description = "Detection patterns for the tool 'awesome-web-security' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "awesome-web-security"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "awesome-web-security" nocase ascii wide

    condition:
        any of them
}
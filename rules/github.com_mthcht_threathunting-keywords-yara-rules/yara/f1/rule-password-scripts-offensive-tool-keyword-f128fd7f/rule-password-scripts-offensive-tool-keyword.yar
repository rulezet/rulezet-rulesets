rule rule_Password_Scripts_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Password-Scripts' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Password-Scripts"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Password_Scripts_offensive_tool_keyword = "Password-Scripts" nocase ascii wide

    condition:
        any of them
}
rule rule_default_password_info_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'default-password.info' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "default-password.info"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_default_password_info_offensive_tool_keyword = /https\:\/\/default\-password\.info\// nocase ascii wide

    condition:
        any of them
}
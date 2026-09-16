rule rule_RedHunt_OS_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RedHunt-OS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RedHunt-OS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RedHunt_OS_offensive_tool_keyword = "RedHunt-OS" nocase ascii wide

    condition:
        any of them
}
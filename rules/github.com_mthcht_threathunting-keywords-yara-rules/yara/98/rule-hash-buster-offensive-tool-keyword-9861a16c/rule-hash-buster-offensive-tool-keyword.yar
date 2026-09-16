rule rule_Hash_Buster_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Hash-Buster' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hash-Buster"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Hash_Buster_offensive_tool_keyword = "Hash-Buster" nocase ascii wide

    condition:
        any of them
}
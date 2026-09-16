rule rule_hacktricks_xyz_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'hacktricks.xyz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hacktricks.xyz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_hacktricks_xyz_offensive_tool_keyword = /book\.hacktricks\.xyz\// nocase ascii wide

    condition:
        any of them
}
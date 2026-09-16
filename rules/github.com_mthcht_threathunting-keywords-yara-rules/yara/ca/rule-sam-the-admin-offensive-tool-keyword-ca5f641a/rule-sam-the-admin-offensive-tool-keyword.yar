rule rule_sam_the_admin_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sam-the-admin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sam-the-admin"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_sam_the_admin_offensive_tool_keyword = /\/utils\/addcomputer\.py/ nocase ascii wide
                        $string2_sam_the_admin_offensive_tool_keyword = /sam_the_admin\.py/ nocase ascii wide

    condition:
        any of them
}
rule rule_scp_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'scp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "scp"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_scp_greyware_tool_keyword = /scp\s.{0,1000}\s.{0,1000}\@.{0,1000}\:/ nocase ascii wide
                        $string2_scp_greyware_tool_keyword = /scp\s.{0,1000}\@.{0,1000}\:.{0,1000}\s/ nocase ascii wide

    condition:
        any of them
}
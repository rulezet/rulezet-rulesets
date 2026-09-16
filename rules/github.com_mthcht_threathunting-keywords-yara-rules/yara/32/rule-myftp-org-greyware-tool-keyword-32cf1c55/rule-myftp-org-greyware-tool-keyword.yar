rule rule_myftp_org_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'myftp.org' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "myftp.org"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_myftp_org_greyware_tool_keyword = /\.myftp\.org/ nocase ascii wide

    condition:
        any of them
}
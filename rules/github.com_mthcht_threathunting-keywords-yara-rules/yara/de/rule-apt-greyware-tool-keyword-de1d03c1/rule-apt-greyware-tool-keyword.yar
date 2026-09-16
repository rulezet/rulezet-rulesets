rule rule_APT_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'APT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "APT"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_APT_greyware_tool_keyword = /APT\:\:Update\:\:Pre\-Invoke\s.{0,1000}\}/

    condition:
        any of them
}
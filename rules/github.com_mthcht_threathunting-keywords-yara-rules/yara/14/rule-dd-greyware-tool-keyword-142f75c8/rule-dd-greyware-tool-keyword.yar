rule rule_dd_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dd' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dd"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_dd_greyware_tool_keyword = "dd if=/dev/nul" nocase ascii wide
                        $string2_dd_greyware_tool_keyword = "dd if=/dev/zero" nocase ascii wide
                        $string3_dd_greyware_tool_keyword = /sudo\sdd\sif\=\/dev\/zero\sbs\=1000\scount\=5\sof\=.{0,1000}log/

    condition:
        any of them
}
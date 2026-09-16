rule rule_WMIcmd_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WMIcmd' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WMIcmd"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WMIcmd_offensive_tool_keyword = /WMIcmd\.exe/ nocase ascii wide

    condition:
        any of them
}
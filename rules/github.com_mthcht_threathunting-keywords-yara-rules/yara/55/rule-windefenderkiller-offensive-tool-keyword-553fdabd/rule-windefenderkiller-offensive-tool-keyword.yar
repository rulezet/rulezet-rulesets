rule rule_WinDefenderKiller_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WinDefenderKiller' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WinDefenderKiller"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WinDefenderKiller_offensive_tool_keyword = " winDefKiller " nocase ascii wide
                        $string2_WinDefenderKiller_offensive_tool_keyword = /disableWinDef\.cpp/ nocase ascii wide
                        $string3_WinDefenderKiller_offensive_tool_keyword = /reverseDisableWinDef\.cpp/ nocase ascii wide
                        $string4_WinDefenderKiller_offensive_tool_keyword = /RevWinDefKiller\.exe/ nocase ascii wide
                        $string5_WinDefenderKiller_offensive_tool_keyword = "WinDefenderKiller" nocase ascii wide
                        $string6_WinDefenderKiller_offensive_tool_keyword = /winDefKiller\.exe/ nocase ascii wide

    condition:
        any of them
}
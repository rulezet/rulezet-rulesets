rule WinDefenderKiller
{
    meta:
        description = "Detection patterns for the tool 'WinDefenderKiller' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WinDefenderKiller"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " winDefKiller " nocase ascii wide
                        $string2 = /disableWinDef\.cpp/ nocase ascii wide
                        $string3 = /reverseDisableWinDef\.cpp/ nocase ascii wide
                        $string4 = /RevWinDefKiller\.exe/ nocase ascii wide
                        $string5 = "WinDefenderKiller" nocase ascii wide
                        $string6 = /winDefKiller\.exe/ nocase ascii wide

    condition:
        any of them
}
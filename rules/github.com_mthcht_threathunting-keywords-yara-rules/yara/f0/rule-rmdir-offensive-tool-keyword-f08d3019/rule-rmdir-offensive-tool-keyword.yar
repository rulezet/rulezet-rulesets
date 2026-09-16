rule rule_rmdir_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rmdir' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rmdir"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_rmdir_offensive_tool_keyword = /rmdir\sC\:\\ProgramData\\Microsoft\\Windows\sDefender\\Quarantine\\Entries\s\/S/ nocase ascii wide
                        $string2_rmdir_offensive_tool_keyword = /rmdir\sC\:\\ProgramData\\Microsoft\\Windows\sDefender\\Quarantine\\ResourceData\s\/S/ nocase ascii wide

    condition:
        any of them
}
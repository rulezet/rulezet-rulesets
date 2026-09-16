rule rule_RegHiveBackup_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RegHiveBackup' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RegHiveBackup"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RegHiveBackup_offensive_tool_keyword = /\/reghivebackup\.zip/ nocase ascii wide
                        $string2_RegHiveBackup_offensive_tool_keyword = /\\RegHiveBackup\.cfg/ nocase ascii wide
                        $string3_RegHiveBackup_offensive_tool_keyword = /\\reghivebackup\.zip/ nocase ascii wide
                        $string4_RegHiveBackup_offensive_tool_keyword = /\\Root\\InventoryApplicationFile\\reghivebackup/ nocase ascii wide
                        $string5_RegHiveBackup_offensive_tool_keyword = ">RegHiveBackup<" nocase ascii wide
                        $string6_RegHiveBackup_offensive_tool_keyword = /RegHiveBackup\.exe/ nocase ascii wide

    condition:
        any of them
}
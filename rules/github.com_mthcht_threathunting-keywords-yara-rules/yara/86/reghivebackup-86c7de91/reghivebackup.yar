rule RegHiveBackup
{
    meta:
        description = "Detection patterns for the tool 'RegHiveBackup' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RegHiveBackup"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/reghivebackup\.zip/ nocase ascii wide
                        $string2 = /\\RegHiveBackup\.cfg/ nocase ascii wide
                        $string3 = /\\reghivebackup\.zip/ nocase ascii wide
                        $string4 = /\\Root\\InventoryApplicationFile\\reghivebackup/ nocase ascii wide
                        $string5 = ">RegHiveBackup<" nocase ascii wide
                        $string6 = /RegHiveBackup\.exe/ nocase ascii wide

    condition:
        any of them
}
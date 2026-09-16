rule Dispossessor
{
    meta:
        description = "Detection patterns for the tool 'Dispossessor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dispossessor"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\\BEST_uninstallTool\.exe/ nocase ascii wide
                        $string2 = /\\findspn\.ps1/ nocase ascii wide

    condition:
        any of them
}
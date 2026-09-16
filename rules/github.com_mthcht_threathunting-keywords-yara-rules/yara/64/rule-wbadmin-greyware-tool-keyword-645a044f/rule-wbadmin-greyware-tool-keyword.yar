rule rule_wbadmin_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wbadmin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wbadmin"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_wbadmin_greyware_tool_keyword = "wbadmin delete backup" nocase ascii wide
                        $string2_wbadmin_greyware_tool_keyword = "wbadmin delete catalog -quiet" nocase ascii wide
                        $string3_wbadmin_greyware_tool_keyword = "wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest" nocase ascii wide
                        $string4_wbadmin_greyware_tool_keyword = "wbadmin DELETE SYSTEMSTATEBACKUP" nocase ascii wide

    condition:
        any of them
}
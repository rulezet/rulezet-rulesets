rule wbadmin
{
    meta:
        description = "Detection patterns for the tool 'wbadmin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wbadmin"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "wbadmin delete backup" nocase ascii wide
                        $string2 = "wbadmin delete catalog -quiet" nocase ascii wide
                        $string3 = "wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest" nocase ascii wide
                        $string4 = "wbadmin DELETE SYSTEMSTATEBACKUP" nocase ascii wide

    condition:
        any of them
}
rule rule_Priv2Admin_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Priv2Admin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Priv2Admin"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Priv2Admin_offensive_tool_keyword = /\/NtQuerySystemInformation\.md/ nocase ascii wide
                        $string2_Priv2Admin_offensive_tool_keyword = /\/NtSetSystemInformation\.md/ nocase ascii wide
                        $string3_Priv2Admin_offensive_tool_keyword = /\/SeBackupPrivilege\.md/ nocase ascii wide
                        $string4_Priv2Admin_offensive_tool_keyword = "gtworek/Priv2Admin" nocase ascii wide

    condition:
        any of them
}
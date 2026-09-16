rule Priv2Admin
{
    meta:
        description = "Detection patterns for the tool 'Priv2Admin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Priv2Admin"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/NtQuerySystemInformation\.md/ nocase ascii wide
                        $string2 = /\/NtSetSystemInformation\.md/ nocase ascii wide
                        $string3 = /\/SeBackupPrivilege\.md/ nocase ascii wide
                        $string4 = "gtworek/Priv2Admin" nocase ascii wide

    condition:
        any of them
}
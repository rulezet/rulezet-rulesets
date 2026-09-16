rule rule_schtasks_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'schtasks' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "schtasks"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_schtasks_greyware_tool_keyword = " /Create /RU SYSTEM /TN MicrosoftEdgeUpdateTaskMachine /TR " nocase ascii wide
                        $string2_schtasks_greyware_tool_keyword = /\s\/create\s\/tn\s\\"SysChecks\\"\s\/tr\sc\:\\temp\\sch\.bat\s/ nocase ascii wide
                        $string3_schtasks_greyware_tool_keyword = /\s\/Create\s\/TN\ssch\.bat\s\/TR\s\\"c\:\\temp\\script\.vbs\\"\s/ nocase ascii wide
                        $string4_schtasks_greyware_tool_keyword = /schtasks\s\/Change\s\/TN\s\\"Microsoft\\Windows\\ExploitGuard\\ExploitGuard\sMDM\spolicy\sRefresh\\"\s\/Disable/ nocase ascii wide
                        $string5_schtasks_greyware_tool_keyword = /schtasks\s\/Change\s\/TN\s\\"Microsoft\\Windows\\Windows\sDefender\\Windows\sDefender\sCache\sMaintenance\\"\s\/Disable/ nocase ascii wide
                        $string6_schtasks_greyware_tool_keyword = /schtasks\s\/Change\s\/TN\s\\"Microsoft\\Windows\\Windows\sDefender\\Windows\sDefender\sCleanup\\"\s\/Disable/ nocase ascii wide
                        $string7_schtasks_greyware_tool_keyword = /schtasks\s\/Change\s\/TN\s\\"Microsoft\\Windows\\Windows\sDefender\\Windows\sDefender\sScheduled\sScan\\"\s\/Disable/ nocase ascii wide
                        $string8_schtasks_greyware_tool_keyword = /schtasks\s\/Change\s\/TN\s\\"Microsoft\\Windows\\Windows\sDefender\\Windows\sDefender\sVerification\\"\s\/Disable/ nocase ascii wide
                        $string9_schtasks_greyware_tool_keyword = /schtasks\s\/Create\s\/RU\sSYSTEM\s\/XML\sc\:\\temp\\/ nocase ascii wide
                        $string10_schtasks_greyware_tool_keyword = "schtasks /query /v /fo LIST" nocase ascii wide
                        $string11_schtasks_greyware_tool_keyword = /schtasks\.exe\s\/create\s\/sc\s.{0,1000}\s\/tr\s\\"\%programdata\%\\sshd\\sshd\.exe\s\-f\s\%programdata\%\\sshd\\config\\sshd_config\\keys\\id_rsa\s\-N\s\-R\s.{0,1000}\s\-o\sStrictHostKeyChecking\=no\s\-o\s/ nocase ascii wide
                        $string12_schtasks_greyware_tool_keyword = /schtasks\.exe\s\/create\s\/sc\sminute\s\/mo\s1\s\/tn\s.{0,1000}\s\/rl\shighest\s\/np\s\/tr\s.{0,1000}\\sshd\\sshd\.exe\s\-f\s.{0,1000}\\sshd\\config\\sshd_config/ nocase ascii wide

    condition:
        any of them
}
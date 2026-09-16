rule rule_StealDhcpSecrets_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'StealDhcpSecrets' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "StealDhcpSecrets"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_StealDhcpSecrets_offensive_tool_keyword = /Can\'t\sfind\sDHCP\sServer\sPID\.\sExiting\./ nocase ascii wide
                        $string2_StealDhcpSecrets_offensive_tool_keyword = /define\sDHCP_KEY\s_T\(\\"SYSTEM\\\\CurrentControlSet\\\\Services\\\\DHCPServer\\\\ServicePrivateData\\"/ nocase ascii wide
                        $string3_StealDhcpSecrets_offensive_tool_keyword = /Impersonation\s\#1\sdone\./ nocase ascii wide
                        $string4_StealDhcpSecrets_offensive_tool_keyword = /Impersonation\s\#1\sfailed\.\sExiting/ nocase ascii wide
                        $string5_StealDhcpSecrets_offensive_tool_keyword = /Impersonation\s\#2\sdone\./ nocase ascii wide
                        $string6_StealDhcpSecrets_offensive_tool_keyword = /Impersonation\s\#2\sfailed\.\sExiting/ nocase ascii wide
                        $string7_StealDhcpSecrets_offensive_tool_keyword = /StealDhcpSecrets\.c/ nocase ascii wide
                        $string8_StealDhcpSecrets_offensive_tool_keyword = /StealDhcpSecrets\.exe/ nocase ascii wide

    condition:
        any of them
}
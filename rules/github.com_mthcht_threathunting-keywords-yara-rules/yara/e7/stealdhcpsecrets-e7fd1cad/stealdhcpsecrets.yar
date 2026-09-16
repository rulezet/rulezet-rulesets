rule StealDhcpSecrets
{
    meta:
        description = "Detection patterns for the tool 'StealDhcpSecrets' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "StealDhcpSecrets"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /Can\'t\sfind\sDHCP\sServer\sPID\.\sExiting\./ nocase ascii wide
                        $string2 = /define\sDHCP_KEY\s_T\(\\"SYSTEM\\\\CurrentControlSet\\\\Services\\\\DHCPServer\\\\ServicePrivateData\\"/ nocase ascii wide
                        $string3 = /Impersonation\s\#1\sdone\./ nocase ascii wide
                        $string4 = /Impersonation\s\#1\sfailed\.\sExiting/ nocase ascii wide
                        $string5 = /Impersonation\s\#2\sdone\./ nocase ascii wide
                        $string6 = /Impersonation\s\#2\sfailed\.\sExiting/ nocase ascii wide
                        $string7 = /StealDhcpSecrets\.c/ nocase ascii wide
                        $string8 = /StealDhcpSecrets\.exe/ nocase ascii wide

    condition:
        any of them
}
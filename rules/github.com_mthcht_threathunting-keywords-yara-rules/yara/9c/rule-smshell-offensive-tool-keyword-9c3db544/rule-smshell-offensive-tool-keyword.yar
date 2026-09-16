rule rule_SMShell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SMShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SMShell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SMShell_offensive_tool_keyword = /\/SMShell\.git/ nocase ascii wide
                        $string2_SMShell_offensive_tool_keyword = "/SMShell/"
                        $string3_SMShell_offensive_tool_keyword = /\-\-mifi\-username\s.{0,1000}\s\-\-mifi\-password\s.{0,1000}\s\-\-number\s\+/ nocase ascii wide
                        $string4_SMShell_offensive_tool_keyword = "persistent-security/SMShell" nocase ascii wide
                        $string5_SMShell_offensive_tool_keyword = /server\-console\.exe\s\+/ nocase ascii wide
                        $string6_SMShell_offensive_tool_keyword = /server\-console\.py\s\-\-mifi\-ip\s/ nocase ascii wide
                        $string7_SMShell_offensive_tool_keyword = /SMShell\.sln/ nocase ascii wide

    condition:
        any of them
}
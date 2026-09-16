rule rule_micr0_shell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'micr0_shell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "micr0_shell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_micr0_shell_offensive_tool_keyword = /\s\-\-execution\sfalse\s\-\-save\sTrue\s\-\-output\s.{0,1000}\.bin/ nocase ascii wide
                        $string2_micr0_shell_offensive_tool_keyword = /\s\-\-ip\s.{0,1000}\s\-\-port\s.{0,1000}\s\-\-type\scmd\s\-\-language\s/ nocase ascii wide
                        $string3_micr0_shell_offensive_tool_keyword = /\s\-\-ip\s.{0,1000}\s\-\-variable\sshellcode\s/ nocase ascii wide
                        $string4_micr0_shell_offensive_tool_keyword = /\/micr0\%20shell\.py/ nocase ascii wide
                        $string5_micr0_shell_offensive_tool_keyword = /\/micr0_shell\.git/ nocase ascii wide
                        $string6_micr0_shell_offensive_tool_keyword = /micr0\sshell\.py/ nocase ascii wide
                        $string7_micr0_shell_offensive_tool_keyword = "micr0_shell-main" nocase ascii wide
                        $string8_micr0_shell_offensive_tool_keyword = /micr0shell\.py\s/ nocase ascii wide
                        $string9_micr0_shell_offensive_tool_keyword = "senzee1984/micr0_shell" nocase ascii wide

    condition:
        any of them
}
rule rule_sRDI_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sRDI' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sRDI"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_sRDI_offensive_tool_keyword = "ConvertTo-Shellcode -" nocase ascii wide
                        $string2_sRDI_offensive_tool_keyword = /ConvertTo\-Shellcode\./ nocase ascii wide
                        $string3_sRDI_offensive_tool_keyword = /ConvertToShellcode\.py/ nocase ascii wide
                        $string4_sRDI_offensive_tool_keyword = "Invoke-Shellcode" nocase ascii wide
                        $string5_sRDI_offensive_tool_keyword = "monoxgas/sRDI" nocase ascii wide
                        $string6_sRDI_offensive_tool_keyword = /ShellcodeRDI\./ nocase ascii wide

    condition:
        any of them
}
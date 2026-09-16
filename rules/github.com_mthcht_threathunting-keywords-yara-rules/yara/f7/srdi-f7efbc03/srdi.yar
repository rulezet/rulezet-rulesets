rule sRDI
{
    meta:
        description = "Detection patterns for the tool 'sRDI' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sRDI"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "ConvertTo-Shellcode -" nocase ascii wide
                        $string2 = /ConvertTo\-Shellcode\./ nocase ascii wide
                        $string3 = /ConvertToShellcode\.py/ nocase ascii wide
                        $string4 = "Invoke-Shellcode" nocase ascii wide
                        $string5 = "monoxgas/sRDI" nocase ascii wide
                        $string6 = /ShellcodeRDI\./ nocase ascii wide

    condition:
        any of them
}
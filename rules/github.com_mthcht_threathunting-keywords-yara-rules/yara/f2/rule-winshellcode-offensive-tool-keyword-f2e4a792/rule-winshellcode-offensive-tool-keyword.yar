rule rule_WinShellcode_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WinShellcode' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WinShellcode"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WinShellcode_offensive_tool_keyword = "DallasFR/WinShellcode" nocase ascii wide
                        $string2_WinShellcode_offensive_tool_keyword = /shellcode_dll\.dll/ nocase ascii wide
                        $string3_WinShellcode_offensive_tool_keyword = /shellcode_dll\\/ nocase ascii wide
                        $string4_WinShellcode_offensive_tool_keyword = /take_shellcode\.bat/ nocase ascii wide
                        $string5_WinShellcode_offensive_tool_keyword = /text_to_shellcode\\.{0,1000}\.exe/ nocase ascii wide
                        $string6_WinShellcode_offensive_tool_keyword = /WinShellcode\.git/ nocase ascii wide
                        $string7_WinShellcode_offensive_tool_keyword = "WinShellcode-main" nocase ascii wide

    condition:
        any of them
}
rule WinShellcode
{
    meta:
        description = "Detection patterns for the tool 'WinShellcode' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WinShellcode"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "DallasFR/WinShellcode" nocase ascii wide
                        $string2 = /shellcode_dll\.dll/ nocase ascii wide
                        $string3 = /shellcode_dll\\/ nocase ascii wide
                        $string4 = /take_shellcode\.bat/ nocase ascii wide
                        $string5 = /text_to_shellcode\\.{0,1000}\.exe/ nocase ascii wide
                        $string6 = /WinShellcode\.git/ nocase ascii wide
                        $string7 = "WinShellcode-main" nocase ascii wide

    condition:
        any of them
}
rule rule_canisrufus_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'canisrufus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "canisrufus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_canisrufus_offensive_tool_keyword = /\scanisrufus\.py/ nocase ascii wide
                        $string2_canisrufus_offensive_tool_keyword = /\sshellcode_generate\.py/ nocase ascii wide
                        $string3_canisrufus_offensive_tool_keyword = " -start-keylogger" nocase ascii wide
                        $string4_canisrufus_offensive_tool_keyword = " -stop-keylogger" nocase ascii wide
                        $string5_canisrufus_offensive_tool_keyword = " windows/meterpreter/reverse_tcp" nocase ascii wide
                        $string6_canisrufus_offensive_tool_keyword = /\/canisrufus\.git/ nocase ascii wide
                        $string7_canisrufus_offensive_tool_keyword = /\/canisrufus\.py/ nocase ascii wide
                        $string8_canisrufus_offensive_tool_keyword = /\/shellcode_generate\.py/ nocase ascii wide
                        $string9_canisrufus_offensive_tool_keyword = /\\canisrufus\.py/ nocase ascii wide
                        $string10_canisrufus_offensive_tool_keyword = /\\shellcode_generate\.py/ nocase ascii wide
                        $string11_canisrufus_offensive_tool_keyword = "54cbfafed88c0b70ede4fe88d02a9de61aee9eb2017c54e7ec0b1c97d755db35" nocase ascii wide
                        $string12_canisrufus_offensive_tool_keyword = "836d7d2ecfbe96f0be128c9b1a4cdbb8e138c502c2420e91713c8b2621aa474a" nocase ascii wide
                        $string13_canisrufus_offensive_tool_keyword = /generate_powershell_shellcode\(/ nocase ascii wide
                        $string14_canisrufus_offensive_tool_keyword = "maldevel/canisrufus" nocase ascii wide
                        $string15_canisrufus_offensive_tool_keyword = "msfvenom -p " nocase ascii wide
                        $string16_canisrufus_offensive_tool_keyword = "'User-Agent':'CanisRufus'" nocase ascii wide

    condition:
        any of them
}
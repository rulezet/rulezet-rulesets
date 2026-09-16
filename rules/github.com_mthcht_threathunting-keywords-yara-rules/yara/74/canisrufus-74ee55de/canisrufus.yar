rule canisrufus
{
    meta:
        description = "Detection patterns for the tool 'canisrufus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "canisrufus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\scanisrufus\.py/ nocase ascii wide
                        $string2 = /\sshellcode_generate\.py/ nocase ascii wide
                        $string3 = " -start-keylogger" nocase ascii wide
                        $string4 = " -stop-keylogger" nocase ascii wide
                        $string5 = " windows/meterpreter/reverse_tcp" nocase ascii wide
                        $string6 = /\/canisrufus\.git/ nocase ascii wide
                        $string7 = /\/canisrufus\.py/ nocase ascii wide
                        $string8 = /\/shellcode_generate\.py/ nocase ascii wide
                        $string9 = /\\canisrufus\.py/ nocase ascii wide
                        $string10 = /\\shellcode_generate\.py/ nocase ascii wide
                        $string11 = "54cbfafed88c0b70ede4fe88d02a9de61aee9eb2017c54e7ec0b1c97d755db35" nocase ascii wide
                        $string12 = "836d7d2ecfbe96f0be128c9b1a4cdbb8e138c502c2420e91713c8b2621aa474a" nocase ascii wide
                        $string13 = /generate_powershell_shellcode\(/ nocase ascii wide
                        $string14 = "maldevel/canisrufus" nocase ascii wide
                        $string15 = "msfvenom -p " nocase ascii wide
                        $string16 = "'User-Agent':'CanisRufus'" nocase ascii wide

    condition:
        any of them
}
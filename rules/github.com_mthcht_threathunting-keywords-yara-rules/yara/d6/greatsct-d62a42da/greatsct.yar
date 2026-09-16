rule GreatSCT
{
    meta:
        description = "Detection patterns for the tool 'GreatSCT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GreatSCT"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-c\s.{0,1000}OBFUSCATION\=.{0,1000}\.ps1/ nocase ascii wide
                        $string2 = " GreatSCT/" nocase ascii wide
                        $string3 = " --list-payloads" nocase ascii wide
                        $string4 = " --msfoptions " nocase ascii wide
                        $string5 = "/Bypass/payloads" nocase ascii wide
                        $string6 = "/GreatSCT/" nocase ascii wide
                        $string7 = "/GreatSCT/GreatSCT"
                        $string8 = "/greatsct-output" nocase ascii wide
                        $string9 = "/regsvcs/meterpreter" nocase ascii wide
                        $string10 = "/regsvr32/shellcode_inject" nocase ascii wide
                        $string11 = "func_get_powershell_dll" nocase ascii wide
                        $string12 = "func_install_wine_dotnettojscript" nocase ascii wide
                        $string13 = "GreatSCT" nocase ascii wide
                        $string14 = /GreatSCT\.git/ nocase ascii wide
                        $string15 = /GreatSCT\.py/ nocase ascii wide
                        $string16 = /invoke_obfuscation\.py/ nocase ascii wide
                        $string17 = "--msfvenom " nocase ascii wide
                        $string18 = "mshta/shellcode_inject" nocase ascii wide

    condition:
        any of them
}
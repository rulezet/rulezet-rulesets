rule rule_GreatSCT_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GreatSCT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GreatSCT"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GreatSCT_offensive_tool_keyword = /\s\-c\s.{0,1000}OBFUSCATION\=.{0,1000}\.ps1/ nocase ascii wide
                        $string2_GreatSCT_offensive_tool_keyword = " GreatSCT/" nocase ascii wide
                        $string3_GreatSCT_offensive_tool_keyword = " --list-payloads" nocase ascii wide
                        $string4_GreatSCT_offensive_tool_keyword = " --msfoptions " nocase ascii wide
                        $string5_GreatSCT_offensive_tool_keyword = "/Bypass/payloads" nocase ascii wide
                        $string6_GreatSCT_offensive_tool_keyword = "/GreatSCT/" nocase ascii wide
                        $string7_GreatSCT_offensive_tool_keyword = "/GreatSCT/GreatSCT"
                        $string8_GreatSCT_offensive_tool_keyword = "/greatsct-output" nocase ascii wide
                        $string9_GreatSCT_offensive_tool_keyword = "/regsvcs/meterpreter" nocase ascii wide
                        $string10_GreatSCT_offensive_tool_keyword = "/regsvr32/shellcode_inject" nocase ascii wide
                        $string11_GreatSCT_offensive_tool_keyword = "func_get_powershell_dll" nocase ascii wide
                        $string12_GreatSCT_offensive_tool_keyword = "func_install_wine_dotnettojscript" nocase ascii wide
                        $string13_GreatSCT_offensive_tool_keyword = "GreatSCT" nocase ascii wide
                        $string14_GreatSCT_offensive_tool_keyword = /GreatSCT\.git/ nocase ascii wide
                        $string15_GreatSCT_offensive_tool_keyword = /GreatSCT\.py/ nocase ascii wide
                        $string16_GreatSCT_offensive_tool_keyword = /invoke_obfuscation\.py/ nocase ascii wide
                        $string17_GreatSCT_offensive_tool_keyword = "--msfvenom " nocase ascii wide
                        $string18_GreatSCT_offensive_tool_keyword = "mshta/shellcode_inject" nocase ascii wide

    condition:
        any of them
}
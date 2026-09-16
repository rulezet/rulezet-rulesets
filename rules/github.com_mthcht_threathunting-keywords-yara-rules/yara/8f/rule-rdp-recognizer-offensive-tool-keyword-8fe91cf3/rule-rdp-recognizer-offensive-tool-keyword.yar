rule rule_RDP_Recognizer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RDP Recognizer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RDP Recognizer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RDP_Recognizer_offensive_tool_keyword = /\/RDP\sRecognizer\.exe/ nocase ascii wide
                        $string2_RDP_Recognizer_offensive_tool_keyword = /\\AppData\\Local\\Temp\\.{0,1000}\\RDP\\Result\\Pass1\.txt/ nocase ascii wide
                        $string3_RDP_Recognizer_offensive_tool_keyword = /\\AppData\\Local\\Temp\\.{0,1000}\\RDP\\Result\\Pass2\.txt/ nocase ascii wide
                        $string4_RDP_Recognizer_offensive_tool_keyword = /\\AppData\\Local\\Temp\\.{0,1000}\\RDP\\Result\\Pass3\.txt/ nocase ascii wide
                        $string5_RDP_Recognizer_offensive_tool_keyword = /\\Brute\sRDP\.rar/ nocase ascii wide
                        $string6_RDP_Recognizer_offensive_tool_keyword = /\\RDP\sRecognizer\.exe/ nocase ascii wide
                        $string7_RDP_Recognizer_offensive_tool_keyword = /\\RDP\sRecognizer\.pdb/ nocase ascii wide
                        $string8_RDP_Recognizer_offensive_tool_keyword = /\\RDP\sRecognizer1\.exe/ nocase ascii wide
                        $string9_RDP_Recognizer_offensive_tool_keyword = /\\RDP\sRecognizer3\.exe/ nocase ascii wide
                        $string10_RDP_Recognizer_offensive_tool_keyword = /\>1047\@exploit\.im\</ nocase ascii wide
                        $string11_RDP_Recognizer_offensive_tool_keyword = ">Penetration test tool<" nocase ascii wide
                        $string12_RDP_Recognizer_offensive_tool_keyword = ">RDP Recognizer<" nocase ascii wide
                        $string13_RDP_Recognizer_offensive_tool_keyword = "1e05c9543989d8f9034dcd87f662ef8319c624a1988b800ad77676f55a2bc538" nocase ascii wide
                        $string14_RDP_Recognizer_offensive_tool_keyword = "491919ffbf3bf3ba309a98d7dce8c3b04e4f269faedd59f57ec1943efe668254" nocase ascii wide
                        $string15_RDP_Recognizer_offensive_tool_keyword = "55d8c97ec4476f7ada4f2991de85f6ddb973ac4634dc0a08e2c731d75c5700b3" nocase ascii wide
                        $string16_RDP_Recognizer_offensive_tool_keyword = "74788c34f3606e482ad28752c14550dc469bb0c04fa72e184a1e457613c2e4f6" nocase ascii wide
                        $string17_RDP_Recognizer_offensive_tool_keyword = "ac0eb86fafd0ca2e1450238cfb023c1c82b6d24fec249623ff1d0e161b7727c6" nocase ascii wide
                        $string18_RDP_Recognizer_offensive_tool_keyword = "ac0eb86fafd0ca2e1450238cfb023c1c82b6d24fec249623ff1d0e161b7727c6" nocase ascii wide
                        $string19_RDP_Recognizer_offensive_tool_keyword = /attrib\s\+r\s\+a\s\+s\s\+h\s\\"\%PROGRAMFILES\%\\Media\splayer\\"\s\/S\s\/D/ nocase ascii wide
                        $string20_RDP_Recognizer_offensive_tool_keyword = "RDP Recognizer Login Parser" nocase ascii wide
                        $string21_RDP_Recognizer_offensive_tool_keyword = /reg\sdelete\s\\"HKLM\\SYSTEM\\Remote\sManipulator\sSystem\\"\s\/f/ nocase ascii wide
                        $string22_RDP_Recognizer_offensive_tool_keyword = /taskkill\s\/f\s\/im\srfusclient\.exe/ nocase ascii wide
                        $string23_RDP_Recognizer_offensive_tool_keyword = /taskkill\s\/f\s\/im\srutserv\.exe/ nocase ascii wide

    condition:
        any of them
}
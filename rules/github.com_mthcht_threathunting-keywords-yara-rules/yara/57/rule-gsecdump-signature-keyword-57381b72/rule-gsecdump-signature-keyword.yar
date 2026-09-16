rule rule_gsecdump_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'gsecdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gsecdump"
        rule_category = "signature_keyword"

    strings:
                        $string1_gsecdump_signature_keyword = "Adware/Gsecdump" nocase ascii wide
                        $string2_gsecdump_signature_keyword = /Hacktool\.Gsecdump/ nocase ascii wide
                        $string3_gsecdump_signature_keyword = "HackTool/Gsecdump" nocase ascii wide
                        $string4_gsecdump_signature_keyword = "HackTool:Win32/Gsecdump" nocase ascii wide
                        $string5_gsecdump_signature_keyword = "HTool-GSECDump" nocase ascii wide
                        $string6_gsecdump_signature_keyword = /PSWTool\.Win64\.Gsecdmp/ nocase ascii wide
                        $string7_gsecdump_signature_keyword = /Win32\/PSWTool\.Gsecdump/ nocase ascii wide
                        $string8_gsecdump_signature_keyword = "Win32:Gsecdump" nocase ascii wide

    condition:
        any of them
}
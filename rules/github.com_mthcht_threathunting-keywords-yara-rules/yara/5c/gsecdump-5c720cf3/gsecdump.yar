rule gsecdump
{
    meta:
        description = "Detection patterns for the tool 'gsecdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gsecdump"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "Adware/Gsecdump" nocase ascii wide
                        $string2 = /Hacktool\.Gsecdump/ nocase ascii wide
                        $string3 = "HackTool/Gsecdump" nocase ascii wide
                        $string4 = "HackTool:Win32/Gsecdump" nocase ascii wide
                        $string5 = "HTool-GSECDump" nocase ascii wide
                        $string6 = /PSWTool\.Win64\.Gsecdmp/ nocase ascii wide
                        $string7 = /Win32\/PSWTool\.Gsecdump/ nocase ascii wide
                        $string8 = "Win32:Gsecdump" nocase ascii wide

    condition:
        any of them
}
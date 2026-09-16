rule rule_PwDump7_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'PwDump7' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PwDump7"
        rule_category = "signature_keyword"

    strings:
                        $string1_PwDump7_signature_keyword = /HackTool\.PasswordStealer/ nocase ascii wide
                        $string2_PwDump7_signature_keyword = /HackTool\.Win32\.PWDump/ nocase ascii wide
                        $string3_PwDump7_signature_keyword = /HackTool\.Win32\.PWDump/ nocase ascii wide
                        $string4_PwDump7_signature_keyword = "HackTool:Win32/PWDump" nocase ascii wide
                        $string5_PwDump7_signature_keyword = /PWCrack\-Pwdump\./ nocase ascii wide
                        $string6_PwDump7_signature_keyword = /PWDump7\sRaw\sPassword\sExtractor\s\(PUA\)/ nocase ascii wide
                        $string7_PwDump7_signature_keyword = "Win32/PWDump" nocase ascii wide

    condition:
        any of them
}
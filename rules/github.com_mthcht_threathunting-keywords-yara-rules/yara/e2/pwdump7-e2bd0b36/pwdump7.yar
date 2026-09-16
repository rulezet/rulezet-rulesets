rule PwDump7
{
    meta:
        description = "Detection patterns for the tool 'PwDump7' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PwDump7"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /HackTool\.PasswordStealer/ nocase ascii wide
                        $string2 = /HackTool\.Win32\.PWDump/ nocase ascii wide
                        $string3 = /HackTool\.Win32\.PWDump/ nocase ascii wide
                        $string4 = "HackTool:Win32/PWDump" nocase ascii wide
                        $string5 = /PWCrack\-Pwdump\./ nocase ascii wide
                        $string6 = /PWDump7\sRaw\sPassword\sExtractor\s\(PUA\)/ nocase ascii wide
                        $string7 = "Win32/PWDump" nocase ascii wide

    condition:
        any of them
}
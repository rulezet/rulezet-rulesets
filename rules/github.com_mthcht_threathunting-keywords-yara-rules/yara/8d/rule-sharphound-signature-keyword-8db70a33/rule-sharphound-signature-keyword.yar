rule rule_sharphound_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'sharphound' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sharphound"
        rule_category = "signature_keyword"

    strings:
                        $string1_sharphound_signature_keyword = " --stealth --secureldap" nocase ascii wide
                        $string2_sharphound_signature_keyword = "3f31295f3435ec6223bbd70a6c0d4620a344e2232c7255dd8fa84ed48aa7a59a" nocase ascii wide
                        $string3_sharphound_signature_keyword = "ATK/BloodH-B" nocase ascii wide
                        $string4_sharphound_signature_keyword = /HackTool\.MSIL\.SharpHound/ nocase ascii wide
                        $string5_sharphound_signature_keyword = /Hacktool\.SharpHound/ nocase ascii wide
                        $string6_sharphound_signature_keyword = "HackTool:W32/SharpHound" nocase ascii wide
                        $string7_sharphound_signature_keyword = /Trojan\:Win32\/Sabsik\.TE\.B\!ml/ nocase ascii wide

    condition:
        any of them
}
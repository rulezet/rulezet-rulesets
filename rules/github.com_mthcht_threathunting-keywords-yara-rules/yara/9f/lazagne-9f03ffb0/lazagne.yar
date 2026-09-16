rule LaZagne
{
    meta:
        description = "Detection patterns for the tool 'LaZagne' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LaZagne"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /Hacktool\.Lazagne/ nocase ascii wide
                        $string2 = "HTool-Lazagne" nocase ascii wide
                        $string3 = /Trojan\.Lazagne/ nocase ascii wide
                        $string4 = /Win32\.LaZagne/ nocase ascii wide
                        $string5 = /Win64\.Lazagne/ nocase ascii wide

    condition:
        any of them
}
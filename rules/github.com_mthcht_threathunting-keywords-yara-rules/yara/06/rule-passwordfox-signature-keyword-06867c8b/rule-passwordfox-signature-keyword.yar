rule rule_passwordfox_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'passwordfox' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "passwordfox"
        rule_category = "signature_keyword"

    strings:
                        $string1_passwordfox_signature_keyword = /Nirsoft\sPasswordFox\s\(PUA\)/ nocase ascii wide
                        $string2_passwordfox_signature_keyword = /PSWTool\.PasswordFox\./ nocase ascii wide
                        $string3_passwordfox_signature_keyword = /PSWTool\.Win64\.FirePass\./ nocase ascii wide

    condition:
        any of them
}
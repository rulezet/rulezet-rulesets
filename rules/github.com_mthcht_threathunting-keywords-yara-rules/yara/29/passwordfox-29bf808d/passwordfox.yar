rule passwordfox
{
    meta:
        description = "Detection patterns for the tool 'passwordfox' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "passwordfox"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /Nirsoft\sPasswordFox\s\(PUA\)/ nocase ascii wide
                        $string2 = /PSWTool\.PasswordFox\./ nocase ascii wide
                        $string3 = /PSWTool\.Win64\.FirePass\./ nocase ascii wide

    condition:
        any of them
}
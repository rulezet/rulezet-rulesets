rule rule_sshdoor_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'sshdoor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshdoor"
        rule_category = "signature_keyword"

    strings:
                        $string1_sshdoor_signature_keyword = /Backdoor\.Linux\.Spyssh\.J/ nocase ascii wide
                        $string2_sshdoor_signature_keyword = /Backdoor\.Linux\.Sshdkit/ nocase ascii wide
                        $string3_sshdoor_signature_keyword = "Linux/SSHDoor" nocase ascii wide
                        $string4_sshdoor_signature_keyword = /Trojan\.Linux\.SSHDoor/ nocase ascii wide

    condition:
        any of them
}
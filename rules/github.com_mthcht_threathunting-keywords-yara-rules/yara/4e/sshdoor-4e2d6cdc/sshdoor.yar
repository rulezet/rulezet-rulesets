rule sshdoor
{
    meta:
        description = "Detection patterns for the tool 'sshdoor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshdoor"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /Backdoor\.Linux\.Spyssh\.J/ nocase ascii wide
                        $string2 = /Backdoor\.Linux\.Sshdkit/ nocase ascii wide
                        $string3 = "Linux/SSHDoor" nocase ascii wide
                        $string4 = /Trojan\.Linux\.SSHDoor/ nocase ascii wide

    condition:
        any of them
}
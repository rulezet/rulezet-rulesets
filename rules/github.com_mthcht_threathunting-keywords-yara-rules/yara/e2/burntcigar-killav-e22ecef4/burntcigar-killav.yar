rule Burntcigar_KillAV
{
    meta:
        description = "Detection patterns for the tool 'Burntcigar KillAV' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Burntcigar KillAV"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /Trojan\.Win32\.KILLAV\.WLEAZ/ nocase ascii wide
                        $string2 = /Trojan\:Win32\/KillAV\.SA/ nocase ascii wide
                        $string3 = "W32/CubaHR_KillAV" nocase ascii wide

    condition:
        any of them
}
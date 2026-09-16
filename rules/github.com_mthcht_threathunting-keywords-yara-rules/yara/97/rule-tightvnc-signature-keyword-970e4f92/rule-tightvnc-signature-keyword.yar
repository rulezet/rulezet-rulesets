rule rule_tightvnc_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'tightvnc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tightvnc"
        rule_category = "signature_keyword"

    strings:
                        $string1_tightvnc_signature_keyword = "RemoteAccess:Win32/TightVNC" nocase ascii wide

    condition:
        any of them
}
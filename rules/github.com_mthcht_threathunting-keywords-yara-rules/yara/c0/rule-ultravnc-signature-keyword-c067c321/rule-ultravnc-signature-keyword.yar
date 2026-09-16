rule rule_UltraVNC_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'UltraVNC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UltraVNC"
        rule_category = "signature_keyword"

    strings:
                        $string1_UltraVNC_signature_keyword = "RemoteAccess:Win32/UltraVNC" nocase ascii wide

    condition:
        any of them
}
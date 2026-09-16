rule rule_vncviewer_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'vncviewer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vncviewer"
        rule_category = "signature_keyword"

    strings:
                        $string1_vncviewer_signature_keyword = "RemoteAccess:Win32/RealVNC" nocase ascii wide

    condition:
        any of them
}
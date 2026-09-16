rule rule_HVNC_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'HVNC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HVNC"
        rule_category = "signature_keyword"

    strings:
                        $string1_HVNC_signature_keyword = "TrojanSpy:Win32/Tinukebot" nocase ascii wide

    condition:
        any of them
}
rule rule_SharpClipboard_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpClipboard' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpClipboard"
        rule_category = "signature_keyword"

    strings:
                        $string1_SharpClipboard_signature_keyword = /MSIL\.ClipBanker/ nocase ascii wide
                        $string2_SharpClipboard_signature_keyword = "MSIL/ClipBanker" nocase ascii wide

    condition:
        any of them
}
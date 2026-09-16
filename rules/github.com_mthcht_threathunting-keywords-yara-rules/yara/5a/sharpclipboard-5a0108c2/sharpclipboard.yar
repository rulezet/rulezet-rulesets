rule SharpClipboard
{
    meta:
        description = "Detection patterns for the tool 'SharpClipboard' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpClipboard"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /MSIL\.ClipBanker/ nocase ascii wide
                        $string2 = "MSIL/ClipBanker" nocase ascii wide

    condition:
        any of them
}
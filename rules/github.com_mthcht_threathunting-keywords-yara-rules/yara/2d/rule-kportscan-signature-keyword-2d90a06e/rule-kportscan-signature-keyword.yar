rule rule_KPortScan_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'KPortScan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KPortScan"
        rule_category = "signature_keyword"

    strings:
                        $string1_KPortScan_signature_keyword = "Win32/Kportscan" nocase ascii wide

    condition:
        any of them
}
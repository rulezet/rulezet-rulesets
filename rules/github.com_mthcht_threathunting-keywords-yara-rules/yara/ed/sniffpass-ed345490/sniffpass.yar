rule SniffPass
{
    meta:
        description = "Detection patterns for the tool 'SniffPass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SniffPass"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "PUA:Win32/PassShow" nocase ascii wide

    condition:
        any of them
}
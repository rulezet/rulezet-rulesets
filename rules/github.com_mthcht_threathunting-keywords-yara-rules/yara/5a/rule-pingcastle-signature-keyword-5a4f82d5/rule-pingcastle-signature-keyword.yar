rule rule_pingcastle_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'pingcastle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pingcastle"
        rule_category = "signature_keyword"

    strings:
                        $string1_pingcastle_signature_keyword = "HackTool:Win32/SmbAgent" nocase ascii wide

    condition:
        any of them
}
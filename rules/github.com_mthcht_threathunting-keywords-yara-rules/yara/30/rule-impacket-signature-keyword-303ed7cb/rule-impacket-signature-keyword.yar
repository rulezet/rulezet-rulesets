rule rule_impacket_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'impacket' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "impacket"
        rule_category = "signature_keyword"

    strings:
                        $string1_impacket_signature_keyword = /HackTool\.Win32\.Mpacket/ nocase ascii wide

    condition:
        any of them
}
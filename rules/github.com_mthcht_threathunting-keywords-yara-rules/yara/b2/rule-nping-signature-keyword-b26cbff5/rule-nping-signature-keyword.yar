rule rule_nping_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'nping' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nping"
        rule_category = "signature_keyword"

    strings:
                        $string1_nping_signature_keyword = /HackTool\:Linux\/ExfiltrationNping\./ nocase ascii wide

    condition:
        any of them
}
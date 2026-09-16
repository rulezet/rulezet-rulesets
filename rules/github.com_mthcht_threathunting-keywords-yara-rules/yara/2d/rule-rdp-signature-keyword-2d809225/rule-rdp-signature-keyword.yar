rule rule_rdp_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'rdp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rdp"
        rule_category = "signature_keyword"

    strings:
                        $string1_rdp_signature_keyword = /Backdoor\:Script\/HustleCon\.A/ nocase ascii wide

    condition:
        any of them
}
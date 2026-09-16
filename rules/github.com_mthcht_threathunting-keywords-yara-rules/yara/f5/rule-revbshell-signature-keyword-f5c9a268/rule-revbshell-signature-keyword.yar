rule rule_revbshell_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'revbshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "revbshell"
        rule_category = "signature_keyword"

    strings:
                        $string1_revbshell_signature_keyword = "ATK/ReVBShel-A" nocase ascii wide
                        $string2_revbshell_signature_keyword = /VBS\.Revbshell/ nocase ascii wide

    condition:
        any of them
}
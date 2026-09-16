rule revbshell
{
    meta:
        description = "Detection patterns for the tool 'revbshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "revbshell"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "ATK/ReVBShel-A" nocase ascii wide
                        $string2 = /VBS\.Revbshell/ nocase ascii wide

    condition:
        any of them
}
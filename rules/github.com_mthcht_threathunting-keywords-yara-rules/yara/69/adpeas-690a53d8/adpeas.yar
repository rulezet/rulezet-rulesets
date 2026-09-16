rule adPEAS
{
    meta:
        description = "Detection patterns for the tool 'adPEAS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adPEAS"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "ATK/Adpeas-A" nocase ascii wide

    condition:
        any of them
}
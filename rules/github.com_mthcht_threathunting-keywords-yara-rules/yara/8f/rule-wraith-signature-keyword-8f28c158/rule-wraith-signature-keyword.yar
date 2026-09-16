rule rule_wraith_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'wraith' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wraith"
        rule_category = "signature_keyword"

    strings:
                        $string1_wraith_signature_keyword = /VirTool\:Python\/Wraitratz\.A/ nocase ascii wide

    condition:
        any of them
}
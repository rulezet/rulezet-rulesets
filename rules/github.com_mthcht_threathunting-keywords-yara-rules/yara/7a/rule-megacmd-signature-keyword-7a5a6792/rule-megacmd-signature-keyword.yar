rule rule_MEGAcmd_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'MEGAcmd' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MEGAcmd"
        rule_category = "signature_keyword"

    strings:
                        $string1_MEGAcmd_signature_keyword = /Hacktool\.MEGAclient/ nocase ascii wide

    condition:
        any of them
}
rule rule_SharpEDRChecker_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpEDRChecker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpEDRChecker"
        rule_category = "signature_keyword"

    strings:
                        $string1_SharpEDRChecker_signature_keyword = /VirTool\:MSIL\/Kanuko\.A\!MTB/ nocase ascii wide

    condition:
        any of them
}
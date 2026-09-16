rule rule_Group3r_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'Group3r' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Group3r"
        rule_category = "signature_keyword"

    strings:
                        $string1_Group3r_signature_keyword = /HackTool\.MSIL\.Gropire\.REDT/ nocase ascii wide
                        $string2_Group3r_signature_keyword = "HackTool:MSIL/Snaffler" nocase ascii wide
                        $string3_Group3r_signature_keyword = /MSIL\/Riskware\.Snaffler/ nocase ascii wide

    condition:
        any of them
}
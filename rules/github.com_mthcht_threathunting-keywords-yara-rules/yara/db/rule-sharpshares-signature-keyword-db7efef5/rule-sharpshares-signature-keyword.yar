rule rule_SharpShares_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpShares' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpShares"
        rule_category = "signature_keyword"

    strings:
                        $string1_SharpShares_signature_keyword = /HackTool\.MSIL\.SharpShares/ nocase ascii wide
                        $string2_SharpShares_signature_keyword = /Hacktool\.Sharpshare/ nocase ascii wide
                        $string3_SharpShares_signature_keyword = /Tool\.SharpSharesNET/ nocase ascii wide
                        $string4_SharpShares_signature_keyword = /Windows\.Hacktool\.SharpShares/ nocase ascii wide

    condition:
        any of them
}
rule SharpShares
{
    meta:
        description = "Detection patterns for the tool 'SharpShares' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpShares"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /HackTool\.MSIL\.SharpShares/ nocase ascii wide
                        $string2 = /Hacktool\.Sharpshare/ nocase ascii wide
                        $string3 = /Tool\.SharpSharesNET/ nocase ascii wide
                        $string4 = /Windows\.Hacktool\.SharpShares/ nocase ascii wide

    condition:
        any of them
}
rule rule_SharpDump_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpDump"
        rule_category = "signature_keyword"

    strings:
                        $string1_SharpDump_signature_keyword = "ATK/SharpDump-A" nocase ascii wide
                        $string2_SharpDump_signature_keyword = /HackTool\.MSIL\.SharpDump32\.SM/ nocase ascii wide
                        $string3_SharpDump_signature_keyword = /Hacktool\.SharpDump/ nocase ascii wide
                        $string4_SharpDump_signature_keyword = "HackTool:MSIL/SharpDump" nocase ascii wide
                        $string5_SharpDump_signature_keyword = /HEUR\:HackTool\.MSIL\.SharpDump\.gen/ nocase ascii wide
                        $string6_SharpDump_signature_keyword = "HTool-GhostPack" nocase ascii wide
                        $string7_SharpDump_signature_keyword = /Win\.Tool\.Sharpdump/ nocase ascii wide
                        $string8_SharpDump_signature_keyword = /Windows\.Hacktool\.SharpDump/ nocase ascii wide

    condition:
        any of them
}
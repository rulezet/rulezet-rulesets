rule SharpDump
{
    meta:
        description = "Detection patterns for the tool 'SharpDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpDump"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "ATK/SharpDump-A" nocase ascii wide
                        $string2 = /HackTool\.MSIL\.SharpDump32\.SM/ nocase ascii wide
                        $string3 = /Hacktool\.SharpDump/ nocase ascii wide
                        $string4 = "HackTool:MSIL/SharpDump" nocase ascii wide
                        $string5 = /HEUR\:HackTool\.MSIL\.SharpDump\.gen/ nocase ascii wide
                        $string6 = "HTool-GhostPack" nocase ascii wide
                        $string7 = /Win\.Tool\.Sharpdump/ nocase ascii wide
                        $string8 = /Windows\.Hacktool\.SharpDump/ nocase ascii wide

    condition:
        any of them
}
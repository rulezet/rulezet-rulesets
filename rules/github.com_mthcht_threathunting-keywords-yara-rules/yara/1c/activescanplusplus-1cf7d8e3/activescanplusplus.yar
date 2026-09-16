rule ActiveScanPlusPlus
{
    meta:
        description = "Detection patterns for the tool 'ActiveScanPlusPlus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ActiveScanPlusPlus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/ActiveScanPlusPlus" nocase ascii wide
                        $string2 = /activeScan\+\+\.py/ nocase ascii wide
                        $string3 = "from burp import " nocase ascii wide

    condition:
        any of them
}
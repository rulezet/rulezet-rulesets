rule rule_ActiveScanPlusPlus_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ActiveScanPlusPlus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ActiveScanPlusPlus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ActiveScanPlusPlus_offensive_tool_keyword = "/ActiveScanPlusPlus" nocase ascii wide
                        $string2_ActiveScanPlusPlus_offensive_tool_keyword = /activeScan\+\+\.py/ nocase ascii wide
                        $string3_ActiveScanPlusPlus_offensive_tool_keyword = "from burp import " nocase ascii wide

    condition:
        any of them
}
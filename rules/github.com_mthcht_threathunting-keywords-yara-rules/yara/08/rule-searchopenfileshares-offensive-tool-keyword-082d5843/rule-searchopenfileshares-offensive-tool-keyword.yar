rule rule_SearchOpenFileShares_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SearchOpenFileShares' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SearchOpenFileShares"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SearchOpenFileShares_offensive_tool_keyword = /\sSearchShares\.ps1/ nocase ascii wide
                        $string2_SearchOpenFileShares_offensive_tool_keyword = /\/SearchShares\.ps1/ nocase ascii wide
                        $string3_SearchOpenFileShares_offensive_tool_keyword = /\\SearchShares\.ps1/ nocase ascii wide
                        $string4_SearchOpenFileShares_offensive_tool_keyword = /\\temp\\OpenFileShares\.txt/ nocase ascii wide
                        $string5_SearchOpenFileShares_offensive_tool_keyword = "FF1F2BA2086D03356EB51ED2208F334EF9E71CA266BFB73AB3CD1F14B494503E" nocase ascii wide

    condition:
        any of them
}
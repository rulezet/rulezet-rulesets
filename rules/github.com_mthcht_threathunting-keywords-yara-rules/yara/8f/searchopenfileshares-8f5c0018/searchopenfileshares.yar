rule SearchOpenFileShares
{
    meta:
        description = "Detection patterns for the tool 'SearchOpenFileShares' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SearchOpenFileShares"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sSearchShares\.ps1/ nocase ascii wide
                        $string2 = /\/SearchShares\.ps1/ nocase ascii wide
                        $string3 = /\\SearchShares\.ps1/ nocase ascii wide
                        $string4 = /\\temp\\OpenFileShares\.txt/ nocase ascii wide
                        $string5 = "FF1F2BA2086D03356EB51ED2208F334EF9E71CA266BFB73AB3CD1F14B494503E" nocase ascii wide

    condition:
        any of them
}
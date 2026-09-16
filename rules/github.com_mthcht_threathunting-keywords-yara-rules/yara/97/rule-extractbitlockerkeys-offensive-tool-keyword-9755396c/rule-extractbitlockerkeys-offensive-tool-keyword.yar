rule rule_ExtractBitlockerKeys_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ExtractBitlockerKeys' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ExtractBitlockerKeys"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ExtractBitlockerKeys_offensive_tool_keyword = /\.ps1\s\-dcip\s.{0,1000}\s\-Username\s.{0,1000}\s\-Password.{0,1000}\s\-ExportToCSV\s.{0,1000}\.csv\s\-ExportToJSON\s.{0,1000}\.json/ nocase ascii wide
                        $string2_ExtractBitlockerKeys_offensive_tool_keyword = /\/ExtractBitlockerKeys\.git/ nocase ascii wide
                        $string3_ExtractBitlockerKeys_offensive_tool_keyword = /ExtractBitLockerKeys.{0,1000}\@podalirius_/ nocase ascii wide
                        $string4_ExtractBitlockerKeys_offensive_tool_keyword = /ExtractBitlockerKeys\.ps1/ nocase ascii wide
                        $string5_ExtractBitlockerKeys_offensive_tool_keyword = /ExtractBitlockerKeys\.py/ nocase ascii wide
                        $string6_ExtractBitlockerKeys_offensive_tool_keyword = "ExtractBitlockerKeys-main" nocase ascii wide
                        $string7_ExtractBitlockerKeys_offensive_tool_keyword = "p0dalirius/ExtractBitlockerKeys" nocase ascii wide

    condition:
        any of them
}
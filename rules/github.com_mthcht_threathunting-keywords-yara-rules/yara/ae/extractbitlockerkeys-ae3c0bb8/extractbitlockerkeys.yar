rule ExtractBitlockerKeys
{
    meta:
        description = "Detection patterns for the tool 'ExtractBitlockerKeys' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ExtractBitlockerKeys"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.ps1\s\-dcip\s.{0,1000}\s\-Username\s.{0,1000}\s\-Password.{0,1000}\s\-ExportToCSV\s.{0,1000}\.csv\s\-ExportToJSON\s.{0,1000}\.json/ nocase ascii wide
                        $string2 = /\/ExtractBitlockerKeys\.git/ nocase ascii wide
                        $string3 = /ExtractBitLockerKeys.{0,1000}\@podalirius_/ nocase ascii wide
                        $string4 = /ExtractBitlockerKeys\.ps1/ nocase ascii wide
                        $string5 = /ExtractBitlockerKeys\.py/ nocase ascii wide
                        $string6 = "ExtractBitlockerKeys-main" nocase ascii wide
                        $string7 = "p0dalirius/ExtractBitlockerKeys" nocase ascii wide

    condition:
        any of them
}
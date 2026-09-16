rule DriverQuery
{
    meta:
        description = "Detection patterns for the tool 'DriverQuery' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DriverQuery"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\[\+\]\sEnumerating\sdriver\sservices\.\.\./ nocase ascii wide
                        $string2 = /DriverQuery\.exe\sno\-msft/ nocase ascii wide
                        $string3 = /OffensiveCSharp.{0,1000}DriverQuery/ nocase ascii wide

    condition:
        any of them
}
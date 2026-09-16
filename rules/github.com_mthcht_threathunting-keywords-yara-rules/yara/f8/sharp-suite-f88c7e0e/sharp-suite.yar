rule Sharp_Suite
{
    meta:
        description = "Detection patterns for the tool 'Sharp-Suite' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Sharp-Suite"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "FuzzySecurity/Sharp-Suite" nocase ascii wide
                        $string2 = /Londor\.exe\s\-t\sCoverage/ nocase ascii wide
                        $string3 = /Londor\.exe\s\-t\sScript/ nocase ascii wide
                        $string4 = /Sharp\-Suite\.git/ nocase ascii wide
                        $string5 = /UrbanBishop\.exe/ nocase ascii wide

    condition:
        any of them
}
rule rule_GPSCoordinates_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GPSCoordinates' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GPSCoordinates"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GPSCoordinates_offensive_tool_keyword = "/master/GPSCoordinates/" nocase ascii wide
                        $string2_GPSCoordinates_offensive_tool_keyword = /\\master\\GPSCoordinates\\/ nocase ascii wide
                        $string3_GPSCoordinates_offensive_tool_keyword = /GPSCoordinates\.exe/ nocase ascii wide

    condition:
        any of them
}
rule GPSCoordinates
{
    meta:
        description = "Detection patterns for the tool 'GPSCoordinates' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GPSCoordinates"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/master/GPSCoordinates/" nocase ascii wide
                        $string2 = /\\master\\GPSCoordinates\\/ nocase ascii wide
                        $string3 = /GPSCoordinates\.exe/ nocase ascii wide

    condition:
        any of them
}
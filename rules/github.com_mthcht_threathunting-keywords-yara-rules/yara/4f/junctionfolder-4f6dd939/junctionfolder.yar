rule JunctionFolder
{
    meta:
        description = "Detection patterns for the tool 'JunctionFolder' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "JunctionFolder"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\%APPDATA\%\/Indexing\./ nocase ascii wide
                        $string2 = "/master/JunctionFolder/" nocase ascii wide
                        $string3 = /\\JunctionFolder\.csproj/ nocase ascii wide
                        $string4 = /C\:\\Users\\.{0,1000}\\AppData\\Roaming\\Indexing\./ nocase ascii wide
                        $string5 = /JunctionFolder\.exe/ nocase ascii wide

    condition:
        any of them
}
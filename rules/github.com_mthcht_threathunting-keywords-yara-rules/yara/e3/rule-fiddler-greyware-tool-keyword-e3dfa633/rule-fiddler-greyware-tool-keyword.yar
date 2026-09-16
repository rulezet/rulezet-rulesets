rule rule_fiddler_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'fiddler' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fiddler"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_fiddler_greyware_tool_keyword = "/download/fiddler/fiddler-everywhere-windows" nocase ascii wide
                        $string2_fiddler_greyware_tool_keyword = /\/Fiddler\sEverywhere\s.{0,1000}\..{0,1000}\..{0,1000}\.exe/ nocase ascii wide
                        $string3_fiddler_greyware_tool_keyword = /\\Fiddler\sEverywhere\s.{0,1000}\..{0,1000}\..{0,1000}\.exe/ nocase ascii wide
                        $string4_fiddler_greyware_tool_keyword = /https\:\/\/www\.telerik\.com\/download\/fiddler\// nocase ascii wide

    condition:
        any of them
}
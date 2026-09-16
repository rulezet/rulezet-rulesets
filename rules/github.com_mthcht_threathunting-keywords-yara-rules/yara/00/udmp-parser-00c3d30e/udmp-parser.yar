rule udmp_parser
{
    meta:
        description = "Detection patterns for the tool 'udmp-parser' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "udmp-parser"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/udmp\-parser\.git/ nocase ascii wide
                        $string2 = "0vercl0k/udmp-parser" nocase ascii wide
                        $string3 = "import udmp_parser" nocase ascii wide
                        $string4 = "install udmp_parser" nocase ascii wide
                        $string5 = /parser\.exe\s\-a\s.{0,1000}\.dmp/ nocase ascii wide
                        $string6 = /parser\.exe\s\-a\s.{0,1000}\.dmp/ nocase ascii wide
                        $string7 = "udmp-parser-main" nocase ascii wide

    condition:
        any of them
}
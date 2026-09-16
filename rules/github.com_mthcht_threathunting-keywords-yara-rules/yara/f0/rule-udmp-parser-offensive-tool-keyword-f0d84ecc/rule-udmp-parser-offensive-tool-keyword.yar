rule rule_udmp_parser_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'udmp-parser' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "udmp-parser"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_udmp_parser_offensive_tool_keyword = /\/udmp\-parser\.git/ nocase ascii wide
                        $string2_udmp_parser_offensive_tool_keyword = "0vercl0k/udmp-parser" nocase ascii wide
                        $string3_udmp_parser_offensive_tool_keyword = "import udmp_parser" nocase ascii wide
                        $string4_udmp_parser_offensive_tool_keyword = "install udmp_parser" nocase ascii wide
                        $string5_udmp_parser_offensive_tool_keyword = /parser\.exe\s\-a\s.{0,1000}\.dmp/ nocase ascii wide
                        $string6_udmp_parser_offensive_tool_keyword = /parser\.exe\s\-a\s.{0,1000}\.dmp/ nocase ascii wide
                        $string7_udmp_parser_offensive_tool_keyword = "udmp-parser-main" nocase ascii wide

    condition:
        any of them
}
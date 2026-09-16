rule rule_MSSprinkler_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MSSprinkler' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MSSprinkler"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MSSprinkler_offensive_tool_keyword = /\smssprinkler\.ps1/ nocase ascii wide
                        $string2_MSSprinkler_offensive_tool_keyword = /\s\-user\suserlist\.txt\s\-pass\spasswordlist\.txt\s/ nocase ascii wide
                        $string3_MSSprinkler_offensive_tool_keyword = /\/MSSprinkler\.git/ nocase ascii wide
                        $string4_MSSprinkler_offensive_tool_keyword = /\/mssprinkler\.ps1/ nocase ascii wide
                        $string5_MSSprinkler_offensive_tool_keyword = /\\mssprinkler\.ps1/ nocase ascii wide
                        $string6_MSSprinkler_offensive_tool_keyword = "c299346734b17df1a8dc47d97145c756938307fbd249837ff4dc697befd2961b" nocase ascii wide
                        $string7_MSSprinkler_offensive_tool_keyword = "Invoke-MSSprinkler" nocase ascii wide
                        $string8_MSSprinkler_offensive_tool_keyword = "TheresAFewConors/MSSprinkler" nocase ascii wide

    condition:
        any of them
}
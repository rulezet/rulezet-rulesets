rule rule_cuddlephish_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'cuddlephish' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cuddlephish"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_cuddlephish_offensive_tool_keyword = /\/cuddlephish\.git/ nocase ascii wide
                        $string2_cuddlephish_offensive_tool_keyword = /\/cuddlephish\.html/ nocase ascii wide
                        $string3_cuddlephish_offensive_tool_keyword = /\/user_data\/.{0,1000}\/keylog\.txt/ nocase ascii wide
                        $string4_cuddlephish_offensive_tool_keyword = "57a0a978ab19598abf7185762834fef1b4dbd4db30d2fb85d411a0e22821df25" nocase ascii wide
                        $string5_cuddlephish_offensive_tool_keyword = "AAABAAMAEBAAAAEAIABoBAAANgAAACAgAAABACAAKBEAAJ4EAAAwMAAAAQAgAGgmAADGFQAAKAAAABAAAAAgAAAAAQAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP39" nocase ascii wide
                        $string6_cuddlephish_offensive_tool_keyword = /browser\.keylog_file\.write/ nocase ascii wide
                        $string7_cuddlephish_offensive_tool_keyword = /cuddlephish.{0,1000}stealer\.js/ nocase ascii wide
                        $string8_cuddlephish_offensive_tool_keyword = "cuddlephish-main" nocase ascii wide
                        $string9_cuddlephish_offensive_tool_keyword = "fkasler/cuddlephish" nocase ascii wide
                        $string10_cuddlephish_offensive_tool_keyword = /http\:\/\/localhost\:58082\/broadcast\?id\=/ nocase ascii wide
                        $string11_cuddlephish_offensive_tool_keyword = /listen\(58082.{0,1000}\s\'0\.0\.0\.0\'/ nocase ascii wide
                        $string12_cuddlephish_offensive_tool_keyword = /node\sstealer\.js\s/ nocase ascii wide
                        $string13_cuddlephish_offensive_tool_keyword = "ws://localhost:58082" nocase ascii wide

    condition:
        any of them
}
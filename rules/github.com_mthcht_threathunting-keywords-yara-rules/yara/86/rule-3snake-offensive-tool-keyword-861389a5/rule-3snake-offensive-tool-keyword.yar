rule rule__3snake_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool '3snake' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "3snake"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1__3snake_offensive_tool_keyword = /\.\/snake/
                        $string2__3snake_offensive_tool_keyword = /\/3snake\.git/ nocase ascii wide
                        $string3__3snake_offensive_tool_keyword = /\/passwd_tracer\.c/
                        $string4__3snake_offensive_tool_keyword = /\/sudo_tracer\.c/
                        $string5__3snake_offensive_tool_keyword = /\/tracers_fuzzer\.cc/ nocase ascii wide
                        $string6__3snake_offensive_tool_keyword = "3snake-master" nocase ascii wide
                        $string7__3snake_offensive_tool_keyword = "blendin/3snake" nocase ascii wide

    condition:
        any of them
}
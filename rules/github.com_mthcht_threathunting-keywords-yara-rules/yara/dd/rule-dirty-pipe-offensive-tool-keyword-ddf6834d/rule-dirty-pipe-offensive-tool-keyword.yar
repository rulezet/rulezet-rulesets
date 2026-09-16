rule rule_dirty_pipe_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dirty-pipe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dirty-pipe"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dirty_pipe_offensive_tool_keyword = /\.\/exploit\s\/etc\/passwd\s1\s.{0,1000}cat\s\/etc\/passwd/
                        $string2_dirty_pipe_offensive_tool_keyword = "/0xIronGoat/dirty-pipe" nocase ascii wide

    condition:
        any of them
}
rule dirty_pipe
{
    meta:
        description = "Detection patterns for the tool 'dirty-pipe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dirty-pipe"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\/exploit\s\/etc\/passwd\s1\s.{0,1000}cat\s\/etc\/passwd/
                        $string2 = "/0xIronGoat/dirty-pipe" nocase ascii wide

    condition:
        any of them
}
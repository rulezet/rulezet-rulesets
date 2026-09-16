rule rule_pendulum_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pendulum' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pendulum"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_pendulum_offensive_tool_keyword = /\/pendulum\.git/
                        $string2_pendulum_offensive_tool_keyword = /\/src\/pendulum\.c/
                        $string3_pendulum_offensive_tool_keyword = /\/src\/pendulum\.h/
                        $string4_pendulum_offensive_tool_keyword = "kyleavery/pendulum"

    condition:
        any of them
}
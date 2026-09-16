rule pendulum
{
    meta:
        description = "Detection patterns for the tool 'pendulum' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pendulum"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/pendulum\.git/
                        $string2 = /\/src\/pendulum\.c/
                        $string3 = /\/src\/pendulum\.h/
                        $string4 = "kyleavery/pendulum"

    condition:
        any of them
}
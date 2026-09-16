rule rule_sudoSnatch_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sudoSnatch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sudoSnatch"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_sudoSnatch_offensive_tool_keyword = "/credentials/SudoSnatch"
                        $string2_sudoSnatch_offensive_tool_keyword = /nIFS\=.{0,1000}\sread\s\-s\spass\\necho\s\-e\s.{0,1000}User\=.{0,1000}\$\(whoami\).{0,1000}Password\=.{0,1000}\$pass.{0,1000}\>\s\/var\/tmp/

    condition:
        any of them
}
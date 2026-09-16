rule tsh
{
    meta:
        description = "Detection patterns for the tool 'tsh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tsh"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/bin/tshd"
                        $string2 = "/tmp/tshd"
                        $string3 = "creaktive/tsh"
                        $string4 = /devine\@cr0\.net/
                        $string5 = /tsh_runshell\(/

    condition:
        any of them
}
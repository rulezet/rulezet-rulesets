rule rule_tsh_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tsh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tsh"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_tsh_offensive_tool_keyword = "/bin/tshd"
                        $string2_tsh_offensive_tool_keyword = "/tmp/tshd"
                        $string3_tsh_offensive_tool_keyword = "creaktive/tsh"
                        $string4_tsh_offensive_tool_keyword = /devine\@cr0\.net/
                        $string5_tsh_offensive_tool_keyword = /tsh_runshell\(/

    condition:
        any of them
}
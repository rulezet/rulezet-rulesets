rule rule_EQGR_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EQGR' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EQGR"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EQGR_offensive_tool_keyword = /\[\-\]\sfailed\sto\sspawn\sshell\:\s\%s/ nocase ascii wide
                        $string2_EQGR_offensive_tool_keyword = /\[\-\]\skernel\snot\svulnerable/ nocase ascii wide
                        $string3_EQGR_offensive_tool_keyword = /abopscript\.txt/ nocase ascii wide
                        $string4_EQGR_offensive_tool_keyword = "chown root %s  chmod 4755 %s  %s"
                        $string5_EQGR_offensive_tool_keyword = /cp\s\/etc\/shadow\s\/tmp\/\./

    condition:
        any of them
}
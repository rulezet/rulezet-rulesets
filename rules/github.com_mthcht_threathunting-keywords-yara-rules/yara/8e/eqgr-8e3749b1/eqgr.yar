rule EQGR
{
    meta:
        description = "Detection patterns for the tool 'EQGR' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EQGR"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\[\-\]\sfailed\sto\sspawn\sshell\:\s\%s/ nocase ascii wide
                        $string2 = /\[\-\]\skernel\snot\svulnerable/ nocase ascii wide
                        $string3 = /abopscript\.txt/ nocase ascii wide
                        $string4 = "chown root %s  chmod 4755 %s  %s"
                        $string5 = /cp\s\/etc\/shadow\s\/tmp\/\./

    condition:
        any of them
}
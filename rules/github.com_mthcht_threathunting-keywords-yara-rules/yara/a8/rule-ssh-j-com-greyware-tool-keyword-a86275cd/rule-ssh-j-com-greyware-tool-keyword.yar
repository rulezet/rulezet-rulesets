rule rule_SSH_J_com_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SSH-J.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SSH-J.com"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_SSH_J_com_greyware_tool_keyword = /\/dropbear\-sshj\.git/ nocase ascii wide
                        $string2_SSH_J_com_greyware_tool_keyword = /ssh\s.{0,1000}\@ssh\-j\.com/ nocase ascii wide
                        $string3_SSH_J_com_greyware_tool_keyword = /sshjmpnoutfqotbj6r3acexiwoalgkth55y5kys7js3px2qqqrwuhqqd\.onion/ nocase ascii wide
                        $string4_SSH_J_com_greyware_tool_keyword = "ValdikSS/dropbear-sshj" nocase ascii wide

    condition:
        any of them
}
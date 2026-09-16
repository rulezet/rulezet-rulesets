rule SSH_J_com
{
    meta:
        description = "Detection patterns for the tool 'SSH-J.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SSH-J.com"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/dropbear\-sshj\.git/ nocase ascii wide
                        $string2 = /ssh\s.{0,1000}\@ssh\-j\.com/ nocase ascii wide
                        $string3 = /sshjmpnoutfqotbj6r3acexiwoalgkth55y5kys7js3px2qqqrwuhqqd\.onion/ nocase ascii wide
                        $string4 = "ValdikSS/dropbear-sshj" nocase ascii wide

    condition:
        any of them
}
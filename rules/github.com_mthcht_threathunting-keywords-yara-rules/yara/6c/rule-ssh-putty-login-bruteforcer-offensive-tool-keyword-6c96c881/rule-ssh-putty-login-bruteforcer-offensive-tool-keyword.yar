rule rule_SSH_PuTTY_login_bruteforcer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SSH-PuTTY-login-bruteforcer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SSH-PuTTY-login-bruteforcer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SSH_PuTTY_login_bruteforcer_offensive_tool_keyword = "ssh-putty-brute -" nocase ascii wide
                        $string2_SSH_PuTTY_login_bruteforcer_offensive_tool_keyword = /ssh\-putty\-brute\.ps1/ nocase ascii wide
                        $string3_SSH_PuTTY_login_bruteforcer_offensive_tool_keyword = "SSH-PuTTY-login-bruteforcer" nocase ascii wide

    condition:
        any of them
}
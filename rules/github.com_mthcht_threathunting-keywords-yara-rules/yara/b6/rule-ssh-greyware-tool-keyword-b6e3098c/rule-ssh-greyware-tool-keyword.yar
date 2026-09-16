rule rule_ssh_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ssh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ssh"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_ssh_greyware_tool_keyword = "bad client public DH value" nocase ascii wide
                        $string2_ssh_greyware_tool_keyword = "fatal: buffer_get_string: bad string" nocase ascii wide
                        $string3_ssh_greyware_tool_keyword = "Local: crc32 compensation attack" nocase ascii wide
                        $string4_ssh_greyware_tool_keyword = "nano /etc/ssh/sshd_config"
                        $string5_ssh_greyware_tool_keyword = /ssh\.exe\s\-L\s0\.0\.0\.0\:445\:127\.0\.0\.1\:445\s/ nocase ascii wide
                        $string6_ssh_greyware_tool_keyword = "vim /etc/ssh/sshd_config"

    condition:
        any of them
}
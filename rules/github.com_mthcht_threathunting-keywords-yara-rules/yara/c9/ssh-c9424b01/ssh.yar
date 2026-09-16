rule ssh
{
    meta:
        description = "Detection patterns for the tool 'ssh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ssh"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "bad client public DH value" nocase ascii wide
                        $string2 = "fatal: buffer_get_string: bad string" nocase ascii wide
                        $string3 = "Local: crc32 compensation attack" nocase ascii wide
                        $string4 = "nano /etc/ssh/sshd_config"
                        $string5 = /ssh\.exe\s\-L\s0\.0\.0\.0\:445\:127\.0\.0\.1\:445\s/ nocase ascii wide
                        $string6 = "vim /etc/ssh/sshd_config"

    condition:
        any of them
}
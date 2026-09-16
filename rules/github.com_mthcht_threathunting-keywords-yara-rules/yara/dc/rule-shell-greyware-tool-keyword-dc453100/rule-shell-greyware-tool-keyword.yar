rule rule_shell_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'shell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shell"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_shell_greyware_tool_keyword = /\/bin\/sh\s\|\snc/
                        $string2_shell_greyware_tool_keyword = "/bin/sh -i <&3 >&3 2>&3"
                        $string3_shell_greyware_tool_keyword = /rm\s\-f\sbackpipe.{0,1000}\smknod\s\/tmp\/backpipe\sp\s\&\&\snc\s/ nocase ascii wide
                        $string4_shell_greyware_tool_keyword = "sc config WinDefend start= disabled" nocase ascii wide
                        $string5_shell_greyware_tool_keyword = "schkconfig off cbdaemon" nocase ascii wide
                        $string6_shell_greyware_tool_keyword = "service cbdaemon stop" nocase ascii wide
                        $string7_shell_greyware_tool_keyword = /socket\(S.{0,1000}PF_INET.{0,1000}SOCK_STREAM.{0,1000}getprotobyname\(.{0,1000}tcp.{0,1000}\)\).{0,1000}if\(connect\(S.{0,1000}sockaddr_in\(\$p.{0,1000}inet_aton\(\$i\)\)\)\)/ nocase ascii wide
                        $string8_shell_greyware_tool_keyword = /STDIN\-\>fdopen\(\$c.{0,1000}r\).{0,1000}\$\~\-\>fdopen\(\$c.{0,1000}w\).{0,1000}system\$_\swhile\<\>/ nocase ascii wide
                        $string9_shell_greyware_tool_keyword = /uname\s\-a.{0,1000}\sw.{0,1000}\sid.{0,1000}\s\/bin\/bash\s\-i/
                        $string10_shell_greyware_tool_keyword = "setenforce 0"

    condition:
        any of them
}
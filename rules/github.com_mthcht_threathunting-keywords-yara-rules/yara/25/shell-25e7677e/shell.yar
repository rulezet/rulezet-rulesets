rule shell
{
    meta:
        description = "Detection patterns for the tool 'shell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shell"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/bin\/sh\s\|\snc/
                        $string2 = "/bin/sh -i <&3 >&3 2>&3"
                        $string3 = /rm\s\-f\sbackpipe.{0,1000}\smknod\s\/tmp\/backpipe\sp\s\&\&\snc\s/ nocase ascii wide
                        $string4 = "sc config WinDefend start= disabled" nocase ascii wide
                        $string5 = "schkconfig off cbdaemon" nocase ascii wide
                        $string6 = "service cbdaemon stop" nocase ascii wide
                        $string7 = /socket\(S.{0,1000}PF_INET.{0,1000}SOCK_STREAM.{0,1000}getprotobyname\(.{0,1000}tcp.{0,1000}\)\).{0,1000}if\(connect\(S.{0,1000}sockaddr_in\(\$p.{0,1000}inet_aton\(\$i\)\)\)\)/ nocase ascii wide
                        $string8 = /STDIN\-\>fdopen\(\$c.{0,1000}r\).{0,1000}\$\~\-\>fdopen\(\$c.{0,1000}w\).{0,1000}system\$_\swhile\<\>/ nocase ascii wide
                        $string9 = /uname\s\-a.{0,1000}\sw.{0,1000}\sid.{0,1000}\s\/bin\/bash\s\-i/
                        $string10 = "setenforce 0"

    condition:
        any of them
}
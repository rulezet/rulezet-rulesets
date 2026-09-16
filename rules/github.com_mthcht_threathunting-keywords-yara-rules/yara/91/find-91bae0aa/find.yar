rule find
{
    meta:
        description = "Detection patterns for the tool 'find' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "find"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\s\/var\/log\s\-type\sf\s\-exec\s.{0,1000}\/tr.{0,1000}\s\-s\s0\s\{\}\s\\/
                        $string2 = " -perm -4000 -o -perm -2000"
                        $string3 = /find\s\.\s\-exec\s\/bin\/sh\s\\\;\s\-quit/
                        $string4 = /find\s\.\s\-perm\s\-2\s\-ls/
                        $string5 = /find\s\.\s\-type\sf\s\-name\s\.bash_history/
                        $string6 = /find\s\.\s\-type\sf\s\-name\s\.fetchmailrc/
                        $string7 = /find\s\.\s\-type\sf\s\-name\s\.htpasswd/
                        $string8 = /find\s\.\s\-type\sf\s\-name\sservice\.pwd/
                        $string9 = /find\s\.\s\-type\sf\s\-perm\s\-02000\s\-ls/
                        $string10 = /find\s\.\s\-type\sf\s\-perm\s\-04000\s\-ls/
                        $string11 = /find\s\/\s\-name\sauthorized_keys\s.{0,1000}\>\s\/dev\/null/
                        $string12 = "find / -name ftp"
                        $string13 = "find / -name id_dsa 2>"
                        $string14 = /find\s\/\s\-name\sid_rsa\s.{0,1000}\>\s\/dev\/null/
                        $string15 = "find / -name id_rsa 2>"
                        $string16 = "find / -name netcat"
                        $string17 = /find\s\/\s\-name\stftp.{0,1000}\s/
                        $string18 = "find / -perm /2000 -ls 2>/dev/null"
                        $string19 = /find\s\/\s\-perm\s\+4000\s\-type\sf\s2\>\/dev\/null/
                        $string20 = /find\s\/\s\-perm\s\+8000\s\-ls\s2\>\/dev\/null/
                        $string21 = "find / -perm -1000 -type d 2>/dev/null"
                        $string22 = "find / -perm -2 -ls"
                        $string23 = "find / -perm -2000"
                        $string24 = "find / -perm -4000"
                        $string25 = "find / -perm -4000 -type f "
                        $string26 = "find / -perm -g=s"
                        $string27 = "find / -perm -g=s -o -perm -u=s -type f 2>/dev/null"
                        $string28 = "find / -perm -g=s -type f 2>/dev/null"
                        $string29 = "find / -perm -u=s"
                        $string30 = "find / -perm -u=s -type f 2>/dev/null"
                        $string31 = "find / -perm -u=s -type f 2>/dev/null"
                        $string32 = /find\s\/\s\-perm\s\-u\=s\s\-type\sf\s\-group\s.{0,1000}\/dev\/null/
                        $string33 = /find\s\/\s\-type\sf\s\-name\s\.bash_history/
                        $string34 = /find\s\/\s\-type\sf\s\-name\s\.fetchmailrc/
                        $string35 = /find\s\/\s\-type\sf\s\-name\s\.htpasswd/
                        $string36 = /find\s\/\s\-type\sf\s\-name\sconfig\.inc\.php/
                        $string37 = /find\s\/\s\-type\sf\s\-name\sservice\.pwd/
                        $string38 = "find / -type f -perm -02000 -ls"
                        $string39 = "find / -type f -perm -04000 -ls"
                        $string40 = "find / -uid 0 -perm -4000 -type f "
                        $string41 = "find / -user root -perm -6000 -type f 2>"
                        $string42 = /find\s\/.{0,1000}\s\-perm\s\-04000\s\-o\s\-perm\s\-02000/
                        $string43 = /find\s\/.{0,1000}\s\-perm\s\-u\=s\s\-type\sf\s2\>/
                        $string44 = /find\s\/var\/log\s\-type\sf\s\-exec\struncate\s\-s\s0\s\{\}\s\\/

    condition:
        any of them
}
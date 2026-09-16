rule rule_find_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'find' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "find"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_find_greyware_tool_keyword = /\s\/var\/log\s\-type\sf\s\-exec\s.{0,1000}\/tr.{0,1000}\s\-s\s0\s\{\}\s\\/
                        $string2_find_greyware_tool_keyword = " -perm -4000 -o -perm -2000"
                        $string3_find_greyware_tool_keyword = /find\s\.\s\-exec\s\/bin\/sh\s\\\;\s\-quit/
                        $string4_find_greyware_tool_keyword = /find\s\.\s\-perm\s\-2\s\-ls/
                        $string5_find_greyware_tool_keyword = /find\s\.\s\-type\sf\s\-name\s\.bash_history/
                        $string6_find_greyware_tool_keyword = /find\s\.\s\-type\sf\s\-name\s\.fetchmailrc/
                        $string7_find_greyware_tool_keyword = /find\s\.\s\-type\sf\s\-name\s\.htpasswd/
                        $string8_find_greyware_tool_keyword = /find\s\.\s\-type\sf\s\-name\sservice\.pwd/
                        $string9_find_greyware_tool_keyword = /find\s\.\s\-type\sf\s\-perm\s\-02000\s\-ls/
                        $string10_find_greyware_tool_keyword = /find\s\.\s\-type\sf\s\-perm\s\-04000\s\-ls/
                        $string11_find_greyware_tool_keyword = /find\s\/\s\-name\sauthorized_keys\s.{0,1000}\>\s\/dev\/null/
                        $string12_find_greyware_tool_keyword = "find / -name ftp"
                        $string13_find_greyware_tool_keyword = "find / -name id_dsa 2>"
                        $string14_find_greyware_tool_keyword = /find\s\/\s\-name\sid_rsa\s.{0,1000}\>\s\/dev\/null/
                        $string15_find_greyware_tool_keyword = "find / -name id_rsa 2>"
                        $string16_find_greyware_tool_keyword = "find / -name netcat"
                        $string17_find_greyware_tool_keyword = /find\s\/\s\-name\stftp.{0,1000}\s/
                        $string18_find_greyware_tool_keyword = "find / -perm /2000 -ls 2>/dev/null"
                        $string19_find_greyware_tool_keyword = /find\s\/\s\-perm\s\+4000\s\-type\sf\s2\>\/dev\/null/
                        $string20_find_greyware_tool_keyword = /find\s\/\s\-perm\s\+8000\s\-ls\s2\>\/dev\/null/
                        $string21_find_greyware_tool_keyword = "find / -perm -1000 -type d 2>/dev/null"
                        $string22_find_greyware_tool_keyword = "find / -perm -2 -ls"
                        $string23_find_greyware_tool_keyword = "find / -perm -2000"
                        $string24_find_greyware_tool_keyword = "find / -perm -4000"
                        $string25_find_greyware_tool_keyword = "find / -perm -4000 -type f "
                        $string26_find_greyware_tool_keyword = "find / -perm -g=s"
                        $string27_find_greyware_tool_keyword = "find / -perm -g=s -o -perm -u=s -type f 2>/dev/null"
                        $string28_find_greyware_tool_keyword = "find / -perm -g=s -type f 2>/dev/null"
                        $string29_find_greyware_tool_keyword = "find / -perm -u=s"
                        $string30_find_greyware_tool_keyword = "find / -perm -u=s -type f 2>/dev/null"
                        $string31_find_greyware_tool_keyword = "find / -perm -u=s -type f 2>/dev/null"
                        $string32_find_greyware_tool_keyword = /find\s\/\s\-perm\s\-u\=s\s\-type\sf\s\-group\s.{0,1000}\/dev\/null/
                        $string33_find_greyware_tool_keyword = /find\s\/\s\-type\sf\s\-name\s\.bash_history/
                        $string34_find_greyware_tool_keyword = /find\s\/\s\-type\sf\s\-name\s\.fetchmailrc/
                        $string35_find_greyware_tool_keyword = /find\s\/\s\-type\sf\s\-name\s\.htpasswd/
                        $string36_find_greyware_tool_keyword = /find\s\/\s\-type\sf\s\-name\sconfig\.inc\.php/
                        $string37_find_greyware_tool_keyword = /find\s\/\s\-type\sf\s\-name\sservice\.pwd/
                        $string38_find_greyware_tool_keyword = "find / -type f -perm -02000 -ls"
                        $string39_find_greyware_tool_keyword = "find / -type f -perm -04000 -ls"
                        $string40_find_greyware_tool_keyword = "find / -uid 0 -perm -4000 -type f "
                        $string41_find_greyware_tool_keyword = "find / -user root -perm -6000 -type f 2>"
                        $string42_find_greyware_tool_keyword = /find\s\/.{0,1000}\s\-perm\s\-04000\s\-o\s\-perm\s\-02000/
                        $string43_find_greyware_tool_keyword = /find\s\/.{0,1000}\s\-perm\s\-u\=s\s\-type\sf\s2\>/
                        $string44_find_greyware_tool_keyword = /find\s\/var\/log\s\-type\sf\s\-exec\struncate\s\-s\s0\s\{\}\s\\/

    condition:
        any of them
}
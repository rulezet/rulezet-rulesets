rule rule_sqlmap_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sqlmap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sqlmap"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_sqlmap_offensive_tool_keyword = " --batch --dbs"
                        $string2_sqlmap_offensive_tool_keyword = " --batch --password"
                        $string3_sqlmap_offensive_tool_keyword = " --check-tor "
                        $string4_sqlmap_offensive_tool_keyword = " --crawl="
                        $string5_sqlmap_offensive_tool_keyword = " --dbms=mysql -u "
                        $string6_sqlmap_offensive_tool_keyword = " --msf-path"
                        $string7_sqlmap_offensive_tool_keyword = " --os-bof"
                        $string8_sqlmap_offensive_tool_keyword = " --os-cmd whoami"
                        $string9_sqlmap_offensive_tool_keyword = " --os-pwn"
                        $string10_sqlmap_offensive_tool_keyword = " --os-smbrelay"
                        $string11_sqlmap_offensive_tool_keyword = " --priv-esc"
                        $string12_sqlmap_offensive_tool_keyword = " --random-agent "
                        $string13_sqlmap_offensive_tool_keyword = " --sql-shell"
                        $string14_sqlmap_offensive_tool_keyword = " --tor "
                        $string15_sqlmap_offensive_tool_keyword = " --tor-port"
                        $string16_sqlmap_offensive_tool_keyword = " --tor-type"
                        $string17_sqlmap_offensive_tool_keyword = /\s\-u\s.{0,1000}http.{0,1000}\s\-\-dbs/
                        $string18_sqlmap_offensive_tool_keyword = /\s\-u\s.{0,1000}http.{0,1000}\s\-\-os\-shell/
                        $string19_sqlmap_offensive_tool_keyword = /\s\-\-union\-char\s.{0,1000}GsFRts2/
                        $string20_sqlmap_offensive_tool_keyword = "/Sqlmap"
                        $string21_sqlmap_offensive_tool_keyword = /\/vulnserver\.py/
                        $string22_sqlmap_offensive_tool_keyword = /backdoor\.asp/
                        $string23_sqlmap_offensive_tool_keyword = /backdoor\.aspx/
                        $string24_sqlmap_offensive_tool_keyword = /backdoor\.jsp/
                        $string25_sqlmap_offensive_tool_keyword = /backdoor\.php/
                        $string26_sqlmap_offensive_tool_keyword = "--batch --dump -T "
                        $string27_sqlmap_offensive_tool_keyword = "data/shell/backdoors"
                        $string28_sqlmap_offensive_tool_keyword = "data/shell/stagers"
                        $string29_sqlmap_offensive_tool_keyword = "--file-read=/etc/passwd"
                        $string30_sqlmap_offensive_tool_keyword = /icmpsh\.exe/ nocase ascii wide
                        $string31_sqlmap_offensive_tool_keyword = /icmpsh_m\.py/
                        $string32_sqlmap_offensive_tool_keyword = /icmpsh\-m\.c/
                        $string33_sqlmap_offensive_tool_keyword = /icmpsh\-m\.pl/
                        $string34_sqlmap_offensive_tool_keyword = /shellcodeexec\.x32/
                        $string35_sqlmap_offensive_tool_keyword = /shellcodeexec\.x64/
                        $string36_sqlmap_offensive_tool_keyword = "sqlmap -"
                        $string37_sqlmap_offensive_tool_keyword = /sqlmap\.conf/
                        $string38_sqlmap_offensive_tool_keyword = /sqlmap\.py/
                        $string39_sqlmap_offensive_tool_keyword = "sqlmapapi -"
                        $string40_sqlmap_offensive_tool_keyword = /sqlmapapi\.py/
                        $string41_sqlmap_offensive_tool_keyword = "sqlmapproject/sqlmap"
                        $string42_sqlmap_offensive_tool_keyword = /xforwardedfor\.py/

    condition:
        any of them
}
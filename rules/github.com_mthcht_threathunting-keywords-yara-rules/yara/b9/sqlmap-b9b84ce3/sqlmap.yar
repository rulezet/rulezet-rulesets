rule sqlmap
{
    meta:
        description = "Detection patterns for the tool 'sqlmap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sqlmap"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --batch --dbs"
                        $string2 = " --batch --password"
                        $string3 = " --check-tor "
                        $string4 = " --crawl="
                        $string5 = " --dbms=mysql -u "
                        $string6 = " --msf-path"
                        $string7 = " --os-bof"
                        $string8 = " --os-cmd whoami"
                        $string9 = " --os-pwn"
                        $string10 = " --os-smbrelay"
                        $string11 = " --priv-esc"
                        $string12 = " --random-agent "
                        $string13 = " --sql-shell"
                        $string14 = " --tor "
                        $string15 = " --tor-port"
                        $string16 = " --tor-type"
                        $string17 = /\s\-u\s.{0,1000}http.{0,1000}\s\-\-dbs/
                        $string18 = /\s\-u\s.{0,1000}http.{0,1000}\s\-\-os\-shell/
                        $string19 = /\s\-\-union\-char\s.{0,1000}GsFRts2/
                        $string20 = "/Sqlmap"
                        $string21 = /\/vulnserver\.py/
                        $string22 = /backdoor\.asp/
                        $string23 = /backdoor\.aspx/
                        $string24 = /backdoor\.jsp/
                        $string25 = /backdoor\.php/
                        $string26 = "--batch --dump -T "
                        $string27 = "data/shell/backdoors"
                        $string28 = "data/shell/stagers"
                        $string29 = "--file-read=/etc/passwd"
                        $string30 = /icmpsh\.exe/ nocase ascii wide
                        $string31 = /icmpsh_m\.py/
                        $string32 = /icmpsh\-m\.c/
                        $string33 = /icmpsh\-m\.pl/
                        $string34 = /shellcodeexec\.x32/
                        $string35 = /shellcodeexec\.x64/
                        $string36 = "sqlmap -"
                        $string37 = /sqlmap\.conf/
                        $string38 = /sqlmap\.py/
                        $string39 = "sqlmapapi -"
                        $string40 = /sqlmapapi\.py/
                        $string41 = "sqlmapproject/sqlmap"
                        $string42 = /xforwardedfor\.py/

    condition:
        any of them
}
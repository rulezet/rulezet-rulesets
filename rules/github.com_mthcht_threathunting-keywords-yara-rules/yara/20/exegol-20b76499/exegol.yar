rule exegol
{
    meta:
        description = "Detection patterns for the tool 'exegol' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "exegol"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\s\-f\s.{0,1000}\.dmp\swindows\.cmdline/ nocase ascii wide
                        $string2 = /\s\-f\s.{0,1000}\.dmp\swindows\.dlllist\s\-\-pid\s/ nocase ascii wide
                        $string3 = /\s\-f\s.{0,1000}\.dmp\swindows\.filescan/ nocase ascii wide
                        $string4 = /\s\-f\s.{0,1000}\.dmp\swindows\.handles\s\-\-pid\s/ nocase ascii wide
                        $string5 = /\s\-f\s.{0,1000}\.dmp\swindows\.info/ nocase ascii wide
                        $string6 = /\s\-f\s.{0,1000}\.dmp\swindows\.malfind/ nocase ascii wide
                        $string7 = /\s\-f\s.{0,1000}\.dmp\swindows\.netscan/ nocase ascii wide
                        $string8 = /\s\-f\s.{0,1000}\.dmp\swindows\.netstat/ nocase ascii wide
                        $string9 = /\s\-f\s.{0,1000}\.dmp\swindows\.pslist/ nocase ascii wide
                        $string10 = /\s\-f\s.{0,1000}\.dmp\swindows\.psscan/ nocase ascii wide
                        $string11 = /\s\-f\s.{0,1000}\.dmp\swindows\.pstree/ nocase ascii wide
                        $string12 = /\s\-f\s.{0,1000}\.dmp\swindows\.registry\.hivelist/ nocase ascii wide
                        $string13 = /\s\-f\s.{0,1000}\.dmp\swindows\.registry\.hivescan/ nocase ascii wide
                        $string14 = /\s\-f\s.{0,1000}\.dmp\swindows\.registry\.printkey/ nocase ascii wide
                        $string15 = /\s\-f\s.{0,1000}\.dmp\swindows\.registry\.printkey.{0,1000}Software\\Microsoft\\Windows\\CurrentVersion/ nocase ascii wide
                        $string16 = /\shttp\-put\-server\.py/ nocase ascii wide
                        $string17 = /\/http\-put\-server\.py/
                        $string18 = /dig\saxfr\s.{0,1000}\s\@/ nocase ascii wide
                        $string19 = /ftp\-server\s\-u\s.{0,1000}\s\-P\s.{0,1000}\s\-p\s2121/ nocase ascii wide
                        $string20 = /nbtscan\s\-r\s.{0,1000}\/24/ nocase ascii wide
                        $string21 = "net rpc group addmem 'Domain admins' " nocase ascii wide
                        $string22 = "net rpc group members 'Domain admins' -U " nocase ascii wide
                        $string23 = /netdiscover\s\-i\s.{0,1000}\s\-r\s.{0,1000}\/24/ nocase ascii wide
                        $string24 = /ngrok\sauthtoken\sAUTHTOKEN\:\:\:https\:\/\/dashboard\.ngrok\.com\/get\-started\/your\-authtoken/ nocase ascii wide
                        $string25 = "nmap -Pn -v -sS -F" nocase ascii wide
                        $string26 = /pwnedornot\.py\s\-d\s/ nocase ascii wide
                        $string27 = "scout aws --profile default -f" nocase ascii wide
                        $string28 = "scout azure --cli" nocase ascii wide
                        $string29 = "screen /dev/ttyACM0 115200" nocase ascii wide
                        $string30 = "snmpwalk -c public -v 1 " nocase ascii wide
                        $string31 = "snmpwalk -c public -v 2c " nocase ascii wide
                        $string32 = /tailscale\sup\s\-\-advertise\-routes\=.{0,1000}\/24/ nocase ascii wide
                        $string33 = "tailscaled --tun=userspace-networking --socks5-server=" nocase ascii wide
                        $string34 = "volatility2 --profile=" nocase ascii wide
                        $string35 = /volatility3\s\-f\s.{0,1000}\.dmp/ nocase ascii wide
                        $string36 = "vulny-code-static-analysis --dir " nocase ascii wide

    condition:
        any of them
}
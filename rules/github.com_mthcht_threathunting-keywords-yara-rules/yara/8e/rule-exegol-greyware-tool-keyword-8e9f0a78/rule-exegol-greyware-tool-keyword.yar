rule rule_exegol_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'exegol' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "exegol"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.cmdline/ nocase ascii wide
                        $string2_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.dlllist\s\-\-pid\s/ nocase ascii wide
                        $string3_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.filescan/ nocase ascii wide
                        $string4_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.handles\s\-\-pid\s/ nocase ascii wide
                        $string5_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.info/ nocase ascii wide
                        $string6_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.malfind/ nocase ascii wide
                        $string7_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.netscan/ nocase ascii wide
                        $string8_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.netstat/ nocase ascii wide
                        $string9_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.pslist/ nocase ascii wide
                        $string10_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.psscan/ nocase ascii wide
                        $string11_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.pstree/ nocase ascii wide
                        $string12_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.registry\.hivelist/ nocase ascii wide
                        $string13_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.registry\.hivescan/ nocase ascii wide
                        $string14_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.registry\.printkey/ nocase ascii wide
                        $string15_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.registry\.printkey.{0,1000}Software\\Microsoft\\Windows\\CurrentVersion/ nocase ascii wide
                        $string16_exegol_greyware_tool_keyword = /\shttp\-put\-server\.py/ nocase ascii wide
                        $string17_exegol_greyware_tool_keyword = /\/http\-put\-server\.py/
                        $string18_exegol_greyware_tool_keyword = /dig\saxfr\s.{0,1000}\s\@/ nocase ascii wide
                        $string19_exegol_greyware_tool_keyword = /ftp\-server\s\-u\s.{0,1000}\s\-P\s.{0,1000}\s\-p\s2121/ nocase ascii wide
                        $string20_exegol_greyware_tool_keyword = /nbtscan\s\-r\s.{0,1000}\/24/ nocase ascii wide
                        $string21_exegol_greyware_tool_keyword = "net rpc group addmem 'Domain admins' " nocase ascii wide
                        $string22_exegol_greyware_tool_keyword = "net rpc group members 'Domain admins' -U " nocase ascii wide
                        $string23_exegol_greyware_tool_keyword = /netdiscover\s\-i\s.{0,1000}\s\-r\s.{0,1000}\/24/ nocase ascii wide
                        $string24_exegol_greyware_tool_keyword = /ngrok\sauthtoken\sAUTHTOKEN\:\:\:https\:\/\/dashboard\.ngrok\.com\/get\-started\/your\-authtoken/ nocase ascii wide
                        $string25_exegol_greyware_tool_keyword = "nmap -Pn -v -sS -F" nocase ascii wide
                        $string26_exegol_greyware_tool_keyword = /pwnedornot\.py\s\-d\s/ nocase ascii wide
                        $string27_exegol_greyware_tool_keyword = "scout aws --profile default -f" nocase ascii wide
                        $string28_exegol_greyware_tool_keyword = "scout azure --cli" nocase ascii wide
                        $string29_exegol_greyware_tool_keyword = "screen /dev/ttyACM0 115200" nocase ascii wide
                        $string30_exegol_greyware_tool_keyword = "snmpwalk -c public -v 1 " nocase ascii wide
                        $string31_exegol_greyware_tool_keyword = "snmpwalk -c public -v 2c " nocase ascii wide
                        $string32_exegol_greyware_tool_keyword = /tailscale\sup\s\-\-advertise\-routes\=.{0,1000}\/24/ nocase ascii wide
                        $string33_exegol_greyware_tool_keyword = "tailscaled --tun=userspace-networking --socks5-server=" nocase ascii wide
                        $string34_exegol_greyware_tool_keyword = "volatility2 --profile=" nocase ascii wide
                        $string35_exegol_greyware_tool_keyword = /volatility3\s\-f\s.{0,1000}\.dmp/ nocase ascii wide
                        $string36_exegol_greyware_tool_keyword = "vulny-code-static-analysis --dir " nocase ascii wide

    condition:
        any of them
}
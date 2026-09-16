rule rule_EvilnoVNC_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EvilnoVNC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EvilnoVNC"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EvilnoVNC_offensive_tool_keyword = " EvilnoVNC by @JoelGMSec"
                        $string2_EvilnoVNC_offensive_tool_keyword = " EvilnoVNC" nocase ascii wide
                        $string3_EvilnoVNC_offensive_tool_keyword = " --vnc localhost:5900 --listen 5980"
                        $string4_EvilnoVNC_offensive_tool_keyword = /\/bin\/bash\s\-c\s\\"php\s\-q\s\-S\s0\.0\.0\.0\:80\s\&\\"\s\>\s\/dev\/null\s2\>\&1/
                        $string5_EvilnoVNC_offensive_tool_keyword = /\/Downloads\/Keylogger\.txt/
                        $string6_EvilnoVNC_offensive_tool_keyword = /\/Downloads\/keypress\.log/
                        $string7_EvilnoVNC_offensive_tool_keyword = /\/EvilnoVNC\.git/ nocase ascii wide
                        $string8_EvilnoVNC_offensive_tool_keyword = /\/noVNC\/index\.html/
                        $string9_EvilnoVNC_offensive_tool_keyword = "/noVNC/utils/novnc_proxy"
                        $string10_EvilnoVNC_offensive_tool_keyword = /\/noVNC\/vnc_lite\.html/
                        $string11_EvilnoVNC_offensive_tool_keyword = /\/start\.sh\sdynamic\s/
                        $string12_EvilnoVNC_offensive_tool_keyword = /\/startVNC\.sh/
                        $string13_EvilnoVNC_offensive_tool_keyword = /\/tmp\/resolution\.txt.{0,1000}server\.sh/
                        $string14_EvilnoVNC_offensive_tool_keyword = "/utils/novnc_proxy"
                        $string15_EvilnoVNC_offensive_tool_keyword = /\\EvilnoVNC/ nocase ascii wide
                        $string16_EvilnoVNC_offensive_tool_keyword = /\\Keylogger\.txt/ nocase ascii wide
                        $string17_EvilnoVNC_offensive_tool_keyword = "1a571ac5b806ffce2605b57753f74653ddb392e5afdb0e49c3e9e8d76e561568" nocase ascii wide
                        $string18_EvilnoVNC_offensive_tool_keyword = "D0:B6:9D:86:6D:AE:B4:E1:CA:F0:C1:F5:4D:82:45:7E:13:06:CD:1A:DE:49:A3:80:DC:21:6A:5C:A8:F4:84:1B"
                        $string19_EvilnoVNC_offensive_tool_keyword = "docker rmi evilnginx" nocase ascii wide
                        $string20_EvilnoVNC_offensive_tool_keyword = "docker rmi evilnovnc" nocase ascii wide
                        $string21_EvilnoVNC_offensive_tool_keyword = /echo\s\'user\sALL\=\(ALL\)\sNOPASSWD\:ALL\'\s\>\>\s\/etc\/sudoers/
                        $string22_EvilnoVNC_offensive_tool_keyword = /EvilnoVNC\s\(\)\s/
                        $string23_EvilnoVNC_offensive_tool_keyword = "EvilnoVNC by @JoelGMSec" nocase ascii wide
                        $string24_EvilnoVNC_offensive_tool_keyword = "EvilnoVNC Server" nocase ascii wide
                        $string25_EvilnoVNC_offensive_tool_keyword = /evilnovnc\.Dockerfile/ nocase ascii wide
                        $string26_EvilnoVNC_offensive_tool_keyword = /EvilnoVNC\/run\.sh/
                        $string27_EvilnoVNC_offensive_tool_keyword = "EvilnoVNC/tmp/"
                        $string28_EvilnoVNC_offensive_tool_keyword = "EvilnoVNC-main" nocase ascii wide
                        $string29_EvilnoVNC_offensive_tool_keyword = /Import\sstealed\ssession\sto\sChromium\.\./ nocase ascii wide
                        $string30_EvilnoVNC_offensive_tool_keyword = /JoelGMSec\s\-\shttps\:\/\/darkbyte\.net/
                        $string31_EvilnoVNC_offensive_tool_keyword = "JoelGMSec/EvilnoVNC" nocase ascii wide
                        $string32_EvilnoVNC_offensive_tool_keyword = /keylogger\.py/ nocase ascii wide
                        $string33_EvilnoVNC_offensive_tool_keyword = /kiosk\.sh.{0,1000}startVNC\.sh/
                        $string34_EvilnoVNC_offensive_tool_keyword = "nandydark/Linux-keylogger"
                        $string35_EvilnoVNC_offensive_tool_keyword = "novnc_proxy --vnc localhost:"
                        $string36_EvilnoVNC_offensive_tool_keyword = /php\s\-q\s\-S\s0\.0\.0\.0\:8111/
                        $string37_EvilnoVNC_offensive_tool_keyword = "Wanetty inspired by @JoelGMSec"

    condition:
        any of them
}
rule rule_PyExfil_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PyExfil' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PyExfil"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PyExfil_offensive_tool_keyword = /\/audio\/exfiltrator\.py/ nocase ascii wide
                        $string2_PyExfil_offensive_tool_keyword = /\/bgp_exfil\.py/ nocase ascii wide
                        $string3_PyExfil_offensive_tool_keyword = /\/http_exfiltration\.py/ nocase ascii wide
                        $string4_PyExfil_offensive_tool_keyword = /\/icmp_exfiltration\.py/
                        $string5_PyExfil_offensive_tool_keyword = /\/pop_exfil_client\.py/ nocase ascii wide
                        $string6_PyExfil_offensive_tool_keyword = /\/pop_exfil_server\.py/ nocase ascii wide
                        $string7_PyExfil_offensive_tool_keyword = /\/PyExfil\.git/ nocase ascii wide
                        $string8_PyExfil_offensive_tool_keyword = "/PyExfil/pyexfil/" nocase ascii wide
                        $string9_PyExfil_offensive_tool_keyword = /\/spoofIPs_client\.py/ nocase ascii wide
                        $string10_PyExfil_offensive_tool_keyword = /\/wifiPayload\/client\.py/ nocase ascii wide
                        $string11_PyExfil_offensive_tool_keyword = /\/wifiPayload\/server\.py/ nocase ascii wide
                        $string12_PyExfil_offensive_tool_keyword = /\\audio\\exfiltrator\.py/ nocase ascii wide
                        $string13_PyExfil_offensive_tool_keyword = /\\bgp_exfil\.py/ nocase ascii wide
                        $string14_PyExfil_offensive_tool_keyword = /\\http_exfiltration\.py/ nocase ascii wide
                        $string15_PyExfil_offensive_tool_keyword = /\\icmp_exfiltration\.py/ nocase ascii wide
                        $string16_PyExfil_offensive_tool_keyword = /\\pop_exfil_client\.py/ nocase ascii wide
                        $string17_PyExfil_offensive_tool_keyword = /\\pop_exfil_server\.py/ nocase ascii wide
                        $string18_PyExfil_offensive_tool_keyword = /\\PyExfil\\pyexfil\\/ nocase ascii wide
                        $string19_PyExfil_offensive_tool_keyword = /\\spoofIPs_client\.py/ nocase ascii wide
                        $string20_PyExfil_offensive_tool_keyword = /\\wifiPayload\\client\.py/ nocase ascii wide
                        $string21_PyExfil_offensive_tool_keyword = /\\wifiPayload\\server\.py/ nocase ascii wide
                        $string22_PyExfil_offensive_tool_keyword = /A\sPython\spackage\sfor\sdata\sexfiltration\./ nocase ascii wide
                        $string23_PyExfil_offensive_tool_keyword = "cd PyExfil" nocase ascii wide
                        $string24_PyExfil_offensive_tool_keyword = /encode\sbaseImage\.jpg\s\/etc\/passwd\snewImage\.jpg/
                        $string25_PyExfil_offensive_tool_keyword = "FILE_TO_EXFIL = \"" nocase ascii wide
                        $string26_PyExfil_offensive_tool_keyword = "pip install --user PyExfil" nocase ascii wide
                        $string27_PyExfil_offensive_tool_keyword = /pyexfil\.Comm\.AllJoyn/ nocase ascii wide
                        $string28_PyExfil_offensive_tool_keyword = /pyexfil\.Comm\.DNSoTLS\.client/ nocase ascii wide
                        $string29_PyExfil_offensive_tool_keyword = /pyexfil\.Comm\.DNSoTLS\.server/ nocase ascii wide
                        $string30_PyExfil_offensive_tool_keyword = /pyexfil\.Comm\.GQUIC/ nocase ascii wide
                        $string31_PyExfil_offensive_tool_keyword = /pyexfil\.Comm\.jetdirect\.communicator/ nocase ascii wide
                        $string32_PyExfil_offensive_tool_keyword = /pyexfil\.Comm\.MDNS/ nocase ascii wide
                        $string33_PyExfil_offensive_tool_keyword = /pyexfil\.Comm\.NTP_Body\.client/ nocase ascii wide
                        $string34_PyExfil_offensive_tool_keyword = /pyexfil\.Comm\.NTP_Body\.server/ nocase ascii wide
                        $string35_PyExfil_offensive_tool_keyword = /pyexfil\.HTTPS\.https_client/ nocase ascii wide
                        $string36_PyExfil_offensive_tool_keyword = /pyexfil\.HTTPS\.https_server/ nocase ascii wide
                        $string37_PyExfil_offensive_tool_keyword = /pyexfil\.includes\.data_generator/ nocase ascii wide
                        $string38_PyExfil_offensive_tool_keyword = /pyexfil\.includes\.encryption_wrappers/ nocase ascii wide
                        $string39_PyExfil_offensive_tool_keyword = /pyexfil\.includes\.exceptions/ nocase ascii wide
                        $string40_PyExfil_offensive_tool_keyword = /pyexfil\.includes\.general/ nocase ascii wide
                        $string41_PyExfil_offensive_tool_keyword = /pyexfil\.includes\.image_manipulation/ nocase ascii wide
                        $string42_PyExfil_offensive_tool_keyword = /pyexfil\.includes\.prepare/ nocase ascii wide
                        $string43_PyExfil_offensive_tool_keyword = /PyExfil\.MoriRT\.com/ nocase ascii wide
                        $string44_PyExfil_offensive_tool_keyword = /pyexfil\.network/ nocase ascii wide
                        $string45_PyExfil_offensive_tool_keyword = /pyexfil\.network\.DB_LSP\.dblsp/ nocase ascii wide
                        $string46_PyExfil_offensive_tool_keyword = /pyexfil\.network\.FTP\.ftp_exfil/ nocase ascii wide
                        $string47_PyExfil_offensive_tool_keyword = /pyexfil\.network\.HTTP_Cookies\.http_exfiltration/ nocase ascii wide
                        $string48_PyExfil_offensive_tool_keyword = /pyexfil\.network\.HTTPResp\.client/ nocase ascii wide
                        $string49_PyExfil_offensive_tool_keyword = /pyexfil\.network\.ICMP\.icmp_exfiltration/ nocase ascii wide
                        $string50_PyExfil_offensive_tool_keyword = /pyexfil\.network\.SpoofIP\.spoofIPs_client/ nocase ascii wide
                        $string51_PyExfil_offensive_tool_keyword = /pyexfil\.physical\.qr\.generator/ nocase ascii wide
                        $string52_PyExfil_offensive_tool_keyword = /pyexfil\.physical\.wifiPayload\.client/ nocase ascii wide
                        $string53_PyExfil_offensive_tool_keyword = /pyexfil\.Stega\.binoffset\.binoffset/ nocase ascii wide
                        $string54_PyExfil_offensive_tool_keyword = "PYEXFIL_DEFAULT_PASSWORD" nocase ascii wide
                        $string55_PyExfil_offensive_tool_keyword = /pyExfil\-latest\.zip/ nocase ascii wide
                        $string56_PyExfil_offensive_tool_keyword = "PyExfil-master" nocase ascii wide
                        $string57_PyExfil_offensive_tool_keyword = "ytisf/PyExfil" nocase ascii wide

    condition:
        any of them
}
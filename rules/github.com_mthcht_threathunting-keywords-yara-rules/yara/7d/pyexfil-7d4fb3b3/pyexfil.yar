rule PyExfil
{
    meta:
        description = "Detection patterns for the tool 'PyExfil' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PyExfil"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/audio\/exfiltrator\.py/ nocase ascii wide
                        $string2 = /\/bgp_exfil\.py/ nocase ascii wide
                        $string3 = /\/http_exfiltration\.py/ nocase ascii wide
                        $string4 = /\/icmp_exfiltration\.py/
                        $string5 = /\/pop_exfil_client\.py/ nocase ascii wide
                        $string6 = /\/pop_exfil_server\.py/ nocase ascii wide
                        $string7 = /\/PyExfil\.git/ nocase ascii wide
                        $string8 = "/PyExfil/pyexfil/" nocase ascii wide
                        $string9 = /\/spoofIPs_client\.py/ nocase ascii wide
                        $string10 = /\/wifiPayload\/client\.py/ nocase ascii wide
                        $string11 = /\/wifiPayload\/server\.py/ nocase ascii wide
                        $string12 = /\\audio\\exfiltrator\.py/ nocase ascii wide
                        $string13 = /\\bgp_exfil\.py/ nocase ascii wide
                        $string14 = /\\http_exfiltration\.py/ nocase ascii wide
                        $string15 = /\\icmp_exfiltration\.py/ nocase ascii wide
                        $string16 = /\\pop_exfil_client\.py/ nocase ascii wide
                        $string17 = /\\pop_exfil_server\.py/ nocase ascii wide
                        $string18 = /\\PyExfil\\pyexfil\\/ nocase ascii wide
                        $string19 = /\\spoofIPs_client\.py/ nocase ascii wide
                        $string20 = /\\wifiPayload\\client\.py/ nocase ascii wide
                        $string21 = /\\wifiPayload\\server\.py/ nocase ascii wide
                        $string22 = /A\sPython\spackage\sfor\sdata\sexfiltration\./ nocase ascii wide
                        $string23 = "cd PyExfil" nocase ascii wide
                        $string24 = /encode\sbaseImage\.jpg\s\/etc\/passwd\snewImage\.jpg/
                        $string25 = "FILE_TO_EXFIL = \"" nocase ascii wide
                        $string26 = "pip install --user PyExfil" nocase ascii wide
                        $string27 = /pyexfil\.Comm\.AllJoyn/ nocase ascii wide
                        $string28 = /pyexfil\.Comm\.DNSoTLS\.client/ nocase ascii wide
                        $string29 = /pyexfil\.Comm\.DNSoTLS\.server/ nocase ascii wide
                        $string30 = /pyexfil\.Comm\.GQUIC/ nocase ascii wide
                        $string31 = /pyexfil\.Comm\.jetdirect\.communicator/ nocase ascii wide
                        $string32 = /pyexfil\.Comm\.MDNS/ nocase ascii wide
                        $string33 = /pyexfil\.Comm\.NTP_Body\.client/ nocase ascii wide
                        $string34 = /pyexfil\.Comm\.NTP_Body\.server/ nocase ascii wide
                        $string35 = /pyexfil\.HTTPS\.https_client/ nocase ascii wide
                        $string36 = /pyexfil\.HTTPS\.https_server/ nocase ascii wide
                        $string37 = /pyexfil\.includes\.data_generator/ nocase ascii wide
                        $string38 = /pyexfil\.includes\.encryption_wrappers/ nocase ascii wide
                        $string39 = /pyexfil\.includes\.exceptions/ nocase ascii wide
                        $string40 = /pyexfil\.includes\.general/ nocase ascii wide
                        $string41 = /pyexfil\.includes\.image_manipulation/ nocase ascii wide
                        $string42 = /pyexfil\.includes\.prepare/ nocase ascii wide
                        $string43 = /PyExfil\.MoriRT\.com/ nocase ascii wide
                        $string44 = /pyexfil\.network/ nocase ascii wide
                        $string45 = /pyexfil\.network\.DB_LSP\.dblsp/ nocase ascii wide
                        $string46 = /pyexfil\.network\.FTP\.ftp_exfil/ nocase ascii wide
                        $string47 = /pyexfil\.network\.HTTP_Cookies\.http_exfiltration/ nocase ascii wide
                        $string48 = /pyexfil\.network\.HTTPResp\.client/ nocase ascii wide
                        $string49 = /pyexfil\.network\.ICMP\.icmp_exfiltration/ nocase ascii wide
                        $string50 = /pyexfil\.network\.SpoofIP\.spoofIPs_client/ nocase ascii wide
                        $string51 = /pyexfil\.physical\.qr\.generator/ nocase ascii wide
                        $string52 = /pyexfil\.physical\.wifiPayload\.client/ nocase ascii wide
                        $string53 = /pyexfil\.Stega\.binoffset\.binoffset/ nocase ascii wide
                        $string54 = "PYEXFIL_DEFAULT_PASSWORD" nocase ascii wide
                        $string55 = /pyExfil\-latest\.zip/ nocase ascii wide
                        $string56 = "PyExfil-master" nocase ascii wide
                        $string57 = "ytisf/PyExfil" nocase ascii wide

    condition:
        any of them
}
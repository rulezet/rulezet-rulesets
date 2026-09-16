rule Egress_Assess
{
    meta:
        description = "Detection patterns for the tool 'Egress-Assess' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Egress-Assess"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-client\sftp\s\-ip\s.{0,1000}\s\-Username\s.{0,1000}\s\-Password\s.{0,1000}\s\-Datatype\sssn\s\-Size\s.{0,1000}\s\-Verbose/ nocase ascii wide
                        $string2 = /\s\-client\shttp\s\-ip\s.{0,1000}\s\-Datatype\scc\s\-Size\s.{0,1000}\s\-Port\s.{0,1000}\s\-Loop\s.{0,1000}\s\-Fast\s\-Verbose/ nocase ascii wide
                        $string3 = /\s\-client\sicmp\s\-ip\s.{0,1000}\s\-Datatype\sssn\s\-Report\s\-Verbose/ nocase ascii wide
                        $string4 = /\s\-client\ssmb\s\-ip\s.{0,1000}\s\-Datatype\s.{0,1000}c\:\\.{0,1000}\..{0,1000}\s\-Verbose/ nocase ascii wide
                        $string5 = /\s\-Client\sSMTPOutlook\s\-IP\s.{0,1000}\s\-NoPing\s\-DataType\s.{0,1000}ssn/ nocase ascii wide
                        $string6 = " Egress-Assess's FTP server" nocase ascii wide
                        $string7 = /\setumbot\.py/ nocase ascii wide
                        $string8 = /\sputterpanda\.py/ nocase ascii wide
                        $string9 = " Use-DarkHotel" nocase ascii wide
                        $string10 = /\.py\s\-\-client\sftp\s\-\-username\s.{0,1000}\s\-\-password\s.{0,1000}\s\-\-ip\s.{0,1000}\s\-\-datatype\sssn/ nocase ascii wide
                        $string11 = /\.py\s\-\-client\shttps\s\-\-data\-size\s.{0,1000}\s\-\-ip\s.{0,1000}\s\-\-datatype\scc/ nocase ascii wide
                        $string12 = /\/bin\/read_i\.php\?a1\=step2\-down\-b\&a2\=/ nocase ascii wide
                        $string13 = /\/bin\/read_i\.php\?a1\=step2\-down\-c\&a2\=/ nocase ascii wide
                        $string14 = /\/bin\/read_i\.php\?a1\=step2\-down\-j\&a2\=/ nocase ascii wide
                        $string15 = /\/bin\/read_i\.php\?a1\=step2\-down\-k\&a2\=/ nocase ascii wide
                        $string16 = /\/bin\/read_i\.php\?a1\=step2\-down\-r\&a2\=/ nocase ascii wide
                        $string17 = /\/bin\/read_i\.php\?a1\=step2\-down\-u\&a2\=/ nocase ascii wide
                        $string18 = /\/commandcontrol\/malware.{0,1000}\.py/ nocase ascii wide
                        $string19 = /\/creditcards\.py/ nocase ascii wide
                        $string20 = /\/darkhotel\.py/ nocase ascii wide
                        $string21 = "/Egress-Assess" nocase ascii wide
                        $string22 = /\/servers\/dns_server\.py/ nocase ascii wide
                        $string23 = /\/servers\/icmp_server\.py/ nocase ascii wide
                        $string24 = /\/servers\/smb_server\.py/ nocase ascii wide
                        $string25 = /\/zejius\/2HZG41Zw\/6Vtmo6w4yQ5tnsBHms64\.php/ nocase ascii wide
                        $string26 = /\/zejius\/2HZG41Zw\/fJsnC6G4sFg2wsyn4shb\.bin/ nocase ascii wide
                        $string27 = /\/zejius\/5GPR0iy9\/6Vtmo6w4yQ5tnsBHms64\.php/ nocase ascii wide
                        $string28 = /\/zejius\/5GPR0iy9\/fJsnC6G4sFg2wsyn4shb\.bin/ nocase ascii wide
                        $string29 = /\\creditcards\.py/ nocase ascii wide
                        $string30 = /\\Egress\-Assess/ nocase ascii wide
                        $string31 = /\\servers\\dns_server\.py/ nocase ascii wide
                        $string32 = /\\servers\\icmp_server\.py/ nocase ascii wide
                        $string33 = /\\servers\\smb_server\.py/ nocase ascii wide
                        $string34 = /apt\/etumbot\.py/ nocase ascii wide
                        $string35 = /apt\/putterpanda\.py/ nocase ascii wide
                        $string36 = /autolace\.twilightparadox\.com/ nocase ascii wide
                        $string37 = /automachine\.servequake\.com/ nocase ascii wide
                        $string38 = /b64encode.{0,1000}\.\:\:\:\-989\-\:\:\:\./ nocase ascii wide
                        $string39 = "bHVrZXJlYWxseWlzdGhlbWFubXl0aGFuZGxlZ2VuZA" nocase ascii wide
                        $string40 = "bm90cmVkYW1lY2hlYXRzdG93aW4-" nocase ascii wide
                        $string41 = "c2VydmVyMS5jaWEuZ292" nocase ascii wide
                        $string42 = "catchetumbotifyoucan>" nocase ascii wide
                        $string43 = "cGlpLmZkYS5nb3Y=" nocase ascii wide
                        $string44 = /Copy\-Item\s\-Path\s.{0,1000}\s\-Destination\s\\\\\$IP\\transfer/ nocase ascii wide
                        $string45 = "d2h5aXNwZW5uc3RhdGVzb2JhZGF0Zm9vdGJhbGw" nocase ascii wide
                        $string46 = "darkhotel backdoor" nocase ascii wide
                        $string47 = "DarkHotel C2" nocase ascii wide
                        $string48 = "darkhotel data exfil server" nocase ascii wide
                        $string49 = "darkhotel_headers" nocase ascii wide
                        $string50 = "dGhlU2VtaW5vbGVzYmVhdG5vcmVkYW1l" nocase ascii wide
                        $string51 = "dGhlYnJvbmNvc2FyZWJldHRlcnRoYW5yYXZlbnM-" nocase ascii wide
                        $string52 = "dGhpc2lzYXRlc3RzdHJpbmdkb250Y2F0Y2htZQ--" nocase ascii wide
                        $string53 = "Egress-Assess Exfil Data" nocase ascii wide
                        $string54 = "Egress-Assess Report" nocase ascii wide
                        $string55 = "Egress-Assess transfer share" nocase ascii wide
                        $string56 = "EgressAssess With Attachment" nocase ascii wide
                        $string57 = /Egress\-Assess\./ nocase ascii wide
                        $string58 = /EgressAssess\.ps1/ nocase ascii wide
                        $string59 = "Egress-Assess-master" nocase ascii wide
                        $string60 = "ENDTHISFILETRANSMISSIONEGRESSASSESS" nocase ascii wide
                        $string61 = "ENDTHISFILETRANSMISSIONEGRESSASSESS" nocase ascii wide
                        $string62 = "function Use-Zeus" nocase ascii wide
                        $string63 = "gohaleygoandhackawaythegibson" nocase ascii wide
                        $string64 = "Invoke-EssessAgress" nocase ascii wide
                        $string65 = /microbrownys\.strangled\.net/ nocase ascii wide
                        $string66 = /microchsse\.strangled\.net/ nocase ascii wide
                        $string67 = /microlilics\.crabdance\.com/ nocase ascii wide
                        $string68 = /micronaoko\.jumpingcrab\.com/ nocase ascii wide
                        $string69 = /microplants\.strangled\.net/ nocase ascii wide
                        $string70 = "MIIEoQIBAAKCAQEArJqP/6XFBa88x/DUootMmSzYa3MxcTV9FjNYUomqbQlGzuHa" nocase ascii wide
                        $string71 = /New\-PSDrive\s\-Name\sT\s\-PSProvider\sFileSystem\s\-Root\s\\\\\$IP\\transfer\s/ nocase ascii wide
                        $string72 = "notredamecheatstowin>" nocase ascii wide
                        $string73 = "putterpanda_whoami" nocase ascii wide
                        $string74 = "RU5EVEhJU0ZJTEVUUkFOU01JU1NJT05FR1JFU1NBU1NFU1M=" nocase ascii wide
                        $string75 = /server\@egress\-asses\.com/ nocase ascii wide
                        $string76 = /smbclient\s\\\\\\\\\\\\\\\\.{0,1000}\\\\\\\\TRANSFER\s\-N\s\-p\s.{0,1000}\s\-c\s\\.{0,1000}put\s/ nocase ascii wide
                        $string77 = /tester\@egress\-assess\.com/ nocase ascii wide
                        $string78 = "thisisateststringdontcatchme" nocase ascii wide
                        $string79 = "TVqQAAMAAAAEAAAA" nocase ascii wide
                        $string80 = "U2VtaW5vbGVzd291bGRkZXN0cm95cGVubnN0YXRl" nocase ascii wide
                        $string81 = "Y2F0Y2hldHVtYm90aWZ5b3VjYW4-" nocase ascii wide
                        $string82 = "Yml0c3kubWl0LmVkdQ==" nocase ascii wide
                        $string83 = "YmpwZW5uaXNhbmF3ZXNvbWVmaWdodGVy" nocase ascii wide
                        $string84 = "Z29oYWxleWdvYW5kaGFja2F3YXl0aGVnaWJzb24" nocase ascii wide
                        $string85 = "ZGF0YS5mZGEuZ292" nocase ascii wide
                        $string86 = "ZGIuc3NhLmdvdg==" nocase ascii wide
                        $string87 = "ZXZpZGVuY2UuZmJpLmdvdg==" nocase ascii wide

    condition:
        any of them
}
rule rule_Egress_Assess_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Egress-Assess' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Egress-Assess"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Egress_Assess_offensive_tool_keyword = /\s\-client\sftp\s\-ip\s.{0,100}\s\-Username\s.{0,100}\s\-Password\s.{0,100}\s\-Datatype\sssn\s\-Size\s.{0,100}\s\-Verbose/ nocase ascii wide
                        $string2_Egress_Assess_offensive_tool_keyword = /\s\-client\shttp\s\-ip\s.{0,100}\s\-Datatype\scc\s\-Size\s.{0,100}\s\-Port\s.{0,100}\s\-Loop\s.{0,100}\s\-Fast\s\-Verbose/ nocase ascii wide
                        $string3_Egress_Assess_offensive_tool_keyword = /\s\-client\sicmp\s\-ip\s.{0,100}\s\-Datatype\sssn\s\-Report\s\-Verbose/ nocase ascii wide
                        $string4_Egress_Assess_offensive_tool_keyword = /\s\-client\ssmb\s\-ip\s.{0,100}\s\-Datatype\s.{0,100}c\:\\.{0,100}\..{0,100}\s\-Verbose/ nocase ascii wide
                        $string5_Egress_Assess_offensive_tool_keyword = /\s\-Client\sSMTPOutlook\s\-IP\s.{0,100}\s\-NoPing\s\-DataType\s.{0,100}ssn/ nocase ascii wide
                        $string6_Egress_Assess_offensive_tool_keyword = " Egress-Assess's FTP server" nocase ascii wide
                        $string7_Egress_Assess_offensive_tool_keyword = /\setumbot\.py/ nocase ascii wide
                        $string8_Egress_Assess_offensive_tool_keyword = /\sputterpanda\.py/ nocase ascii wide
                        $string9_Egress_Assess_offensive_tool_keyword = " Use-DarkHotel" nocase ascii wide
                        $string10_Egress_Assess_offensive_tool_keyword = /\.py\s\-\-client\sftp\s\-\-username\s.{0,100}\s\-\-password\s.{0,100}\s\-\-ip\s.{0,100}\s\-\-datatype\sssn/ nocase ascii wide
                        $string11_Egress_Assess_offensive_tool_keyword = /\.py\s\-\-client\shttps\s\-\-data\-size\s.{0,100}\s\-\-ip\s.{0,100}\s\-\-datatype\scc/ nocase ascii wide
                        $string12_Egress_Assess_offensive_tool_keyword = /\/bin\/read_i\.php\?a1\=step2\-down\-b\&a2\=/ nocase ascii wide
                        $string13_Egress_Assess_offensive_tool_keyword = /\/bin\/read_i\.php\?a1\=step2\-down\-c\&a2\=/ nocase ascii wide
                        $string14_Egress_Assess_offensive_tool_keyword = /\/bin\/read_i\.php\?a1\=step2\-down\-j\&a2\=/ nocase ascii wide
                        $string15_Egress_Assess_offensive_tool_keyword = /\/bin\/read_i\.php\?a1\=step2\-down\-k\&a2\=/ nocase ascii wide
                        $string16_Egress_Assess_offensive_tool_keyword = /\/bin\/read_i\.php\?a1\=step2\-down\-r\&a2\=/ nocase ascii wide
                        $string17_Egress_Assess_offensive_tool_keyword = /\/bin\/read_i\.php\?a1\=step2\-down\-u\&a2\=/ nocase ascii wide
                        $string18_Egress_Assess_offensive_tool_keyword = /\/commandcontrol\/malware.{0,100}\.py/ nocase ascii wide
                        $string19_Egress_Assess_offensive_tool_keyword = /\/creditcards\.py/ nocase ascii wide
                        $string20_Egress_Assess_offensive_tool_keyword = /\/darkhotel\.py/ nocase ascii wide
                        $string21_Egress_Assess_offensive_tool_keyword = "/Egress-Assess" nocase ascii wide
                        $string22_Egress_Assess_offensive_tool_keyword = /\/servers\/dns_server\.py/ nocase ascii wide
                        $string23_Egress_Assess_offensive_tool_keyword = /\/servers\/icmp_server\.py/ nocase ascii wide
                        $string24_Egress_Assess_offensive_tool_keyword = /\/servers\/smb_server\.py/ nocase ascii wide
                        $string25_Egress_Assess_offensive_tool_keyword = /\/zejius\/2HZG41Zw\/6Vtmo6w4yQ5tnsBHms64\.php/ nocase ascii wide
                        $string26_Egress_Assess_offensive_tool_keyword = /\/zejius\/2HZG41Zw\/fJsnC6G4sFg2wsyn4shb\.bin/ nocase ascii wide
                        $string27_Egress_Assess_offensive_tool_keyword = /\/zejius\/5GPR0iy9\/6Vtmo6w4yQ5tnsBHms64\.php/ nocase ascii wide
                        $string28_Egress_Assess_offensive_tool_keyword = /\/zejius\/5GPR0iy9\/fJsnC6G4sFg2wsyn4shb\.bin/ nocase ascii wide
                        $string29_Egress_Assess_offensive_tool_keyword = /\\creditcards\.py/ nocase ascii wide
                        $string30_Egress_Assess_offensive_tool_keyword = /\\Egress\-Assess/ nocase ascii wide
                        $string31_Egress_Assess_offensive_tool_keyword = /\\servers\\dns_server\.py/ nocase ascii wide
                        $string32_Egress_Assess_offensive_tool_keyword = /\\servers\\icmp_server\.py/ nocase ascii wide
                        $string33_Egress_Assess_offensive_tool_keyword = /\\servers\\smb_server\.py/ nocase ascii wide
                        $string34_Egress_Assess_offensive_tool_keyword = /apt\/etumbot\.py/ nocase ascii wide
                        $string35_Egress_Assess_offensive_tool_keyword = /apt\/putterpanda\.py/ nocase ascii wide
                        $string36_Egress_Assess_offensive_tool_keyword = /autolace\.twilightparadox\.com/ nocase ascii wide
                        $string37_Egress_Assess_offensive_tool_keyword = /automachine\.servequake\.com/ nocase ascii wide
                        $string38_Egress_Assess_offensive_tool_keyword = /b64encode.{0,100}\.\:\:\:\-989\-\:\:\:\./ nocase ascii wide
                        $string39_Egress_Assess_offensive_tool_keyword = "bHVrZXJlYWxseWlzdGhlbWFubXl0aGFuZGxlZ2VuZA" nocase ascii wide
                        $string40_Egress_Assess_offensive_tool_keyword = "bm90cmVkYW1lY2hlYXRzdG93aW4-" nocase ascii wide
                        $string41_Egress_Assess_offensive_tool_keyword = "c2VydmVyMS5jaWEuZ292" nocase ascii wide
                        $string42_Egress_Assess_offensive_tool_keyword = "catchetumbotifyoucan>" nocase ascii wide
                        $string43_Egress_Assess_offensive_tool_keyword = "cGlpLmZkYS5nb3Y=" nocase ascii wide
                        $string44_Egress_Assess_offensive_tool_keyword = /Copy\-Item\s\-Path\s.{0,100}\s\-Destination\s\\\\\$IP\\transfer/ nocase ascii wide
                        $string45_Egress_Assess_offensive_tool_keyword = "d2h5aXNwZW5uc3RhdGVzb2JhZGF0Zm9vdGJhbGw" nocase ascii wide
                        $string46_Egress_Assess_offensive_tool_keyword = "darkhotel backdoor" nocase ascii wide
                        $string47_Egress_Assess_offensive_tool_keyword = "DarkHotel C2" nocase ascii wide
                        $string48_Egress_Assess_offensive_tool_keyword = "darkhotel data exfil server" nocase ascii wide
                        $string49_Egress_Assess_offensive_tool_keyword = "darkhotel_headers" nocase ascii wide
                        $string50_Egress_Assess_offensive_tool_keyword = "dGhlU2VtaW5vbGVzYmVhdG5vcmVkYW1l" nocase ascii wide
                        $string51_Egress_Assess_offensive_tool_keyword = "dGhlYnJvbmNvc2FyZWJldHRlcnRoYW5yYXZlbnM-" nocase ascii wide
                        $string52_Egress_Assess_offensive_tool_keyword = "dGhpc2lzYXRlc3RzdHJpbmdkb250Y2F0Y2htZQ--" nocase ascii wide
                        $string53_Egress_Assess_offensive_tool_keyword = "Egress-Assess Exfil Data" nocase ascii wide
                        $string54_Egress_Assess_offensive_tool_keyword = "Egress-Assess Report" nocase ascii wide
                        $string55_Egress_Assess_offensive_tool_keyword = "Egress-Assess transfer share" nocase ascii wide
                        $string56_Egress_Assess_offensive_tool_keyword = "EgressAssess With Attachment" nocase ascii wide
                        $string57_Egress_Assess_offensive_tool_keyword = /Egress\-Assess\./ nocase ascii wide
                        $string58_Egress_Assess_offensive_tool_keyword = /EgressAssess\.ps1/ nocase ascii wide
                        $string59_Egress_Assess_offensive_tool_keyword = "Egress-Assess-master" nocase ascii wide
                        $string60_Egress_Assess_offensive_tool_keyword = "ENDTHISFILETRANSMISSIONEGRESSASSESS" nocase ascii wide
                        $string61_Egress_Assess_offensive_tool_keyword = "ENDTHISFILETRANSMISSIONEGRESSASSESS" nocase ascii wide
                        $string62_Egress_Assess_offensive_tool_keyword = "function Use-Zeus" nocase ascii wide
                        $string63_Egress_Assess_offensive_tool_keyword = "gohaleygoandhackawaythegibson" nocase ascii wide
                        $string64_Egress_Assess_offensive_tool_keyword = "Invoke-EssessAgress" nocase ascii wide
                        $string65_Egress_Assess_offensive_tool_keyword = /microbrownys\.strangled\.net/ nocase ascii wide
                        $string66_Egress_Assess_offensive_tool_keyword = /microchsse\.strangled\.net/ nocase ascii wide
                        $string67_Egress_Assess_offensive_tool_keyword = /microlilics\.crabdance\.com/ nocase ascii wide
                        $string68_Egress_Assess_offensive_tool_keyword = /micronaoko\.jumpingcrab\.com/ nocase ascii wide
                        $string69_Egress_Assess_offensive_tool_keyword = /microplants\.strangled\.net/ nocase ascii wide
                        $string70_Egress_Assess_offensive_tool_keyword = "MIIEoQIBAAKCAQEArJqP/6XFBa88x/DUootMmSzYa3MxcTV9FjNYUomqbQlGzuHa" nocase ascii wide
                        $string71_Egress_Assess_offensive_tool_keyword = /New\-PSDrive\s\-Name\sT\s\-PSProvider\sFileSystem\s\-Root\s\\\\\$IP\\transfer\s/ nocase ascii wide
                        $string72_Egress_Assess_offensive_tool_keyword = "notredamecheatstowin>" nocase ascii wide
                        $string73_Egress_Assess_offensive_tool_keyword = "putterpanda_whoami" nocase ascii wide
                        $string74_Egress_Assess_offensive_tool_keyword = "RU5EVEhJU0ZJTEVUUkFOU01JU1NJT05FR1JFU1NBU1NFU1M=" nocase ascii wide
                        $string75_Egress_Assess_offensive_tool_keyword = /server\@egress\-asses\.com/ nocase ascii wide
                        $string76_Egress_Assess_offensive_tool_keyword = /smbclient\s\\\\\\\\\\\\\\\\.{0,100}\\\\\\\\TRANSFER\s\-N\s\-p\s.{0,100}\s\-c\s\\.{0,100}put\s/ nocase ascii wide
                        $string77_Egress_Assess_offensive_tool_keyword = /tester\@egress\-assess\.com/ nocase ascii wide
                        $string78_Egress_Assess_offensive_tool_keyword = "thisisateststringdontcatchme" nocase ascii wide
                        $string79_Egress_Assess_offensive_tool_keyword = "TVqQAAMAAAAEAAAA" nocase ascii wide
                        $string80_Egress_Assess_offensive_tool_keyword = "U2VtaW5vbGVzd291bGRkZXN0cm95cGVubnN0YXRl" nocase ascii wide
                        $string81_Egress_Assess_offensive_tool_keyword = "Y2F0Y2hldHVtYm90aWZ5b3VjYW4-" nocase ascii wide
                        $string82_Egress_Assess_offensive_tool_keyword = "Yml0c3kubWl0LmVkdQ==" nocase ascii wide
                        $string83_Egress_Assess_offensive_tool_keyword = "YmpwZW5uaXNhbmF3ZXNvbWVmaWdodGVy" nocase ascii wide
                        $string84_Egress_Assess_offensive_tool_keyword = "Z29oYWxleWdvYW5kaGFja2F3YXl0aGVnaWJzb24" nocase ascii wide
                        $string85_Egress_Assess_offensive_tool_keyword = "ZGF0YS5mZGEuZ292" nocase ascii wide
                        $string86_Egress_Assess_offensive_tool_keyword = "ZGIuc3NhLmdvdg==" nocase ascii wide
                        $string87_Egress_Assess_offensive_tool_keyword = "ZXZpZGVuY2UuZmJpLmdvdg==" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
rule rule_responder_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'responder' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "responder"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_responder_offensive_tool_keyword = /\sPoisoners\-Session\.log/ nocase ascii wide
                        $string2_responder_offensive_tool_keyword = /\/Analyzer\-Session\.log/
                        $string3_responder_offensive_tool_keyword = /\/FindSQLSrv\.py/ nocase ascii wide
                        $string4_responder_offensive_tool_keyword = /\/NBTNS\.py/ nocase ascii wide
                        $string5_responder_offensive_tool_keyword = /\/poisoners\/.{0,1000}\.py/ nocase ascii wide
                        $string6_responder_offensive_tool_keyword = /\/Poisoners\-Session\.log/
                        $string7_responder_offensive_tool_keyword = /\/Responder\.git/ nocase ascii wide
                        $string8_responder_offensive_tool_keyword = /\/responder\/Responder\.conf\s/ nocase ascii wide
                        $string9_responder_offensive_tool_keyword = /\/Responder\-master\.zip/ nocase ascii wide
                        $string10_responder_offensive_tool_keyword = /\/Responder\-Session\.log/
                        $string11_responder_offensive_tool_keyword = /\/Responder\-Windows\.git/ nocase ascii wide
                        $string12_responder_offensive_tool_keyword = /\/tools\/DHCP\.py/
                        $string13_responder_offensive_tool_keyword = /\\\\Windows\\\\Temp\\\\Results\.txt/ nocase ascii wide
                        $string14_responder_offensive_tool_keyword = /\\BindShell\.exe/ nocase ascii wide
                        $string15_responder_offensive_tool_keyword = /\\cachedump\.py/ nocase ascii wide
                        $string16_responder_offensive_tool_keyword = /\\FTP\-Clear\-Text\-Password\-.{0,1000}\.txt/ nocase ascii wide
                        $string17_responder_offensive_tool_keyword = /\\HTTP\-Clear\-Text\-Password\-.{0,1000}\.txt/ nocase ascii wide
                        $string18_responder_offensive_tool_keyword = /\\HTTP\-NTLMv1\-Client\-.{0,1000}\.txt/ nocase ascii wide
                        $string19_responder_offensive_tool_keyword = /\\HTTP\-NTLMv2\-Client\-.{0,1000}\.txt/ nocase ascii wide
                        $string20_responder_offensive_tool_keyword = /\\IMAP\-Clear\-Text\-Password\-.{0,1000}\.txt/ nocase ascii wide
                        $string21_responder_offensive_tool_keyword = /\\LDAP\-Clear\-Text\-Password\-.{0,1000}\.txt/ nocase ascii wide
                        $string22_responder_offensive_tool_keyword = /\\LDAP\-NTLMv1\-Client\-.{0,1000}\.txt/ nocase ascii wide
                        $string23_responder_offensive_tool_keyword = /\\lsadump\.py/ nocase ascii wide
                        $string24_responder_offensive_tool_keyword = /\\MSSQL\-Clear\-Text\-Password\-.{0,1000}\.txt/ nocase ascii wide
                        $string25_responder_offensive_tool_keyword = /\\MSSQL\-NTLMv1\-Client\-.{0,1000}\.txt/ nocase ascii wide
                        $string26_responder_offensive_tool_keyword = /\\MSSQL\-NTLMv2\-Client\-.{0,1000}\.txt/ nocase ascii wide
                        $string27_responder_offensive_tool_keyword = /\\Poisoners\-Session\.log/ nocase ascii wide
                        $string28_responder_offensive_tool_keyword = /\\POP3\-Clear\-Text\-Password\-.{0,1000}\.txt/ nocase ascii wide
                        $string29_responder_offensive_tool_keyword = /\\pwdump\.py/ nocase ascii wide
                        $string30_responder_offensive_tool_keyword = /\\Responder\-Session\.log/ nocase ascii wide
                        $string31_responder_offensive_tool_keyword = /\\SMB\-Clear\-Text\-Password\-.{0,1000}\.txt/ nocase ascii wide
                        $string32_responder_offensive_tool_keyword = /\\SMB\-NTLMSSPv2\-Client\-.{0,1000}\.txt/ nocase ascii wide
                        $string33_responder_offensive_tool_keyword = /\\SMB\-NTLMv1\-Client\-.{0,1000}\.txt/ nocase ascii wide
                        $string34_responder_offensive_tool_keyword = /\\SMBRelay\-Session\.txt/ nocase ascii wide
                        $string35_responder_offensive_tool_keyword = /\\SMTP\-Clear\-Text\-Password\-.{0,1000}\.txt/ nocase ascii wide
                        $string36_responder_offensive_tool_keyword = /\\Windows\\Temp\\Results\.txt/ nocase ascii wide
                        $string37_responder_offensive_tool_keyword = "0fa31c8c34a370931d8ffe8097e998f778db63e2e036fbd7727a71a0dcf5d28c" nocase ascii wide
                        $string38_responder_offensive_tool_keyword = "3c6898fa2726b6487fcb12b854021b4e23f984e2bcdf5b5fe300c36cec2ad1a4" nocase ascii wide
                        $string39_responder_offensive_tool_keyword = "47d121087c05568fe90a25ef921f9e35d40bc6bec969e33e75337fc9b580f0e8" nocase ascii wide
                        $string40_responder_offensive_tool_keyword = "54a43829632b2b9984076cb2e24c2d4cbd5e50c410eb4320591e3fc347dec662" nocase ascii wide
                        $string41_responder_offensive_tool_keyword = "6a1d85188bb481088fdd202dbb994910de83b05a2b49420faf1dc4a66143918b" nocase ascii wide
                        $string42_responder_offensive_tool_keyword = "89c2214589dff9530c6367d2968ba26cd9533eb279b88dc755b06d66ed575428" nocase ascii wide
                        $string43_responder_offensive_tool_keyword = /BrowserListener\.py/ nocase ascii wide
                        $string44_responder_offensive_tool_keyword = /cert.{0,1000}responder\.crt/ nocase ascii wide
                        $string45_responder_offensive_tool_keyword = /cert.{0,1000}responder\.key/ nocase ascii wide
                        $string46_responder_offensive_tool_keyword = "f2816b74ccb015b5eb7910f0ee389531ffaa0df8bc613d419cc4d4a50e99bb4e" nocase ascii wide
                        $string47_responder_offensive_tool_keyword = "f8a603588cb91acf4c4a745f74326d202f4d63243fefaf048e1076174a18a50a" nocase ascii wide
                        $string48_responder_offensive_tool_keyword = /files\/BindShell\.exe/ nocase ascii wide
                        $string49_responder_offensive_tool_keyword = /files\/BindShell\.exe/ nocase ascii wide
                        $string50_responder_offensive_tool_keyword = /FindSMB2UPTime\.py/ nocase ascii wide
                        $string51_responder_offensive_tool_keyword = /Icmp\-Redirect\.py/ nocase ascii wide
                        $string52_responder_offensive_tool_keyword = "lgandx/Responder-Windows" nocase ascii wide
                        $string53_responder_offensive_tool_keyword = /LLMNR\.py/ nocase ascii wide
                        $string54_responder_offensive_tool_keyword = "MIIEowIBAAKCAQEAunMwNRcEEAUJQSZDeDh/hGmpPEzMr1v9fVYie4uFD33thh1k" nocase ascii wide
                        $string55_responder_offensive_tool_keyword = "netsh firewall set opmode disable" nocase ascii wide
                        $string56_responder_offensive_tool_keyword = /Poisoners\-Session\.log/ nocase ascii wide
                        $string57_responder_offensive_tool_keyword = /Preparing\sWindows\sfor\sResponder\.\.\.\\nDisabling\sNetBIOS/ nocase ascii wide
                        $string58_responder_offensive_tool_keyword = /RelayPackets\.py/ nocase ascii wide
                        $string59_responder_offensive_tool_keyword = /responder\s.{0,1000}\s\-\-lm/ nocase ascii wide
                        $string60_responder_offensive_tool_keyword = "responder -i " nocase ascii wide
                        $string61_responder_offensive_tool_keyword = /Responder\.py/ nocase ascii wide
                        $string62_responder_offensive_tool_keyword = /Responder\\Responder\.exe/ nocase ascii wide
                        $string63_responder_offensive_tool_keyword = "ResponderConfigDump " nocase ascii wide
                        $string64_responder_offensive_tool_keyword = /Responder\-Session\.log/ nocase ascii wide
                        $string65_responder_offensive_tool_keyword = "Responder-Windows" nocase ascii wide
                        $string66_responder_offensive_tool_keyword = /SMBRelay\.py/ nocase ascii wide
                        $string67_responder_offensive_tool_keyword = "SpiderLabs/Responder" nocase ascii wide
                        $string68_responder_offensive_tool_keyword = "wmic /interactive:off nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2" nocase ascii wide

    condition:
        any of them
}
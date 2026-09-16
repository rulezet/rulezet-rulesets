rule responder
{
    meta:
        description = "Detection patterns for the tool 'responder' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "responder"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sPoisoners\-Session\.log/ nocase ascii wide
                        $string2 = /\/Analyzer\-Session\.log/
                        $string3 = /\/FindSQLSrv\.py/ nocase ascii wide
                        $string4 = /\/NBTNS\.py/ nocase ascii wide
                        $string5 = /\/poisoners\/.{0,100}\.py/ nocase ascii wide
                        $string6 = /\/Poisoners\-Session\.log/
                        $string7 = /\/Responder\.git/ nocase ascii wide
                        $string8 = /\/responder\/Responder\.conf\s/ nocase ascii wide
                        $string9 = /\/Responder\-master\.zip/ nocase ascii wide
                        $string10 = /\/Responder\-Session\.log/
                        $string11 = /\/Responder\-Windows\.git/ nocase ascii wide
                        $string12 = /\/tools\/DHCP\.py/
                        $string13 = /\\\\Windows\\\\Temp\\\\Results\.txt/ nocase ascii wide
                        $string14 = /\\BindShell\.exe/ nocase ascii wide
                        $string15 = /\\cachedump\.py/ nocase ascii wide
                        $string16 = /\\FTP\-Clear\-Text\-Password\-.{0,100}\.txt/ nocase ascii wide
                        $string17 = /\\HTTP\-Clear\-Text\-Password\-.{0,100}\.txt/ nocase ascii wide
                        $string18 = /\\HTTP\-NTLMv1\-Client\-.{0,100}\.txt/ nocase ascii wide
                        $string19 = /\\HTTP\-NTLMv2\-Client\-.{0,100}\.txt/ nocase ascii wide
                        $string20 = /\\IMAP\-Clear\-Text\-Password\-.{0,100}\.txt/ nocase ascii wide
                        $string21 = /\\LDAP\-Clear\-Text\-Password\-.{0,100}\.txt/ nocase ascii wide
                        $string22 = /\\LDAP\-NTLMv1\-Client\-.{0,100}\.txt/ nocase ascii wide
                        $string23 = /\\lsadump\.py/ nocase ascii wide
                        $string24 = /\\MSSQL\-Clear\-Text\-Password\-.{0,100}\.txt/ nocase ascii wide
                        $string25 = /\\MSSQL\-NTLMv1\-Client\-.{0,100}\.txt/ nocase ascii wide
                        $string26 = /\\MSSQL\-NTLMv2\-Client\-.{0,100}\.txt/ nocase ascii wide
                        $string27 = /\\Poisoners\-Session\.log/ nocase ascii wide
                        $string28 = /\\POP3\-Clear\-Text\-Password\-.{0,100}\.txt/ nocase ascii wide
                        $string29 = /\\pwdump\.py/ nocase ascii wide
                        $string30 = /\\Responder\-Session\.log/ nocase ascii wide
                        $string31 = /\\SMB\-Clear\-Text\-Password\-.{0,100}\.txt/ nocase ascii wide
                        $string32 = /\\SMB\-NTLMSSPv2\-Client\-.{0,100}\.txt/ nocase ascii wide
                        $string33 = /\\SMB\-NTLMv1\-Client\-.{0,100}\.txt/ nocase ascii wide
                        $string34 = /\\SMBRelay\-Session\.txt/ nocase ascii wide
                        $string35 = /\\SMTP\-Clear\-Text\-Password\-.{0,100}\.txt/ nocase ascii wide
                        $string36 = /\\Windows\\Temp\\Results\.txt/ nocase ascii wide
                        $string37 = "0fa31c8c34a370931d8ffe8097e998f778db63e2e036fbd7727a71a0dcf5d28c" nocase ascii wide
                        $string38 = "3c6898fa2726b6487fcb12b854021b4e23f984e2bcdf5b5fe300c36cec2ad1a4" nocase ascii wide
                        $string39 = "47d121087c05568fe90a25ef921f9e35d40bc6bec969e33e75337fc9b580f0e8" nocase ascii wide
                        $string40 = "54a43829632b2b9984076cb2e24c2d4cbd5e50c410eb4320591e3fc347dec662" nocase ascii wide
                        $string41 = "6a1d85188bb481088fdd202dbb994910de83b05a2b49420faf1dc4a66143918b" nocase ascii wide
                        $string42 = "89c2214589dff9530c6367d2968ba26cd9533eb279b88dc755b06d66ed575428" nocase ascii wide
                        $string43 = /BrowserListener\.py/ nocase ascii wide
                        $string44 = /cert.{0,100}responder\.crt/ nocase ascii wide
                        $string45 = /cert.{0,100}responder\.key/ nocase ascii wide
                        $string46 = "f2816b74ccb015b5eb7910f0ee389531ffaa0df8bc613d419cc4d4a50e99bb4e" nocase ascii wide
                        $string47 = "f8a603588cb91acf4c4a745f74326d202f4d63243fefaf048e1076174a18a50a" nocase ascii wide
                        $string48 = /files\/BindShell\.exe/ nocase ascii wide
                        $string49 = /files\/BindShell\.exe/ nocase ascii wide
                        $string50 = /FindSMB2UPTime\.py/ nocase ascii wide
                        $string51 = /Icmp\-Redirect\.py/ nocase ascii wide
                        $string52 = "lgandx/Responder-Windows" nocase ascii wide
                        $string53 = /LLMNR\.py/ nocase ascii wide
                        $string54 = "MIIEowIBAAKCAQEAunMwNRcEEAUJQSZDeDh/hGmpPEzMr1v9fVYie4uFD33thh1k" nocase ascii wide
                        $string55 = "netsh firewall set opmode disable" nocase ascii wide
                        $string56 = /Poisoners\-Session\.log/ nocase ascii wide
                        $string57 = /Preparing\sWindows\sfor\sResponder\.\.\.\\nDisabling\sNetBIOS/ nocase ascii wide
                        $string58 = /RelayPackets\.py/ nocase ascii wide
                        $string59 = /responder\s.{0,100}\s\-\-lm/ nocase ascii wide
                        $string60 = "responder -i " nocase ascii wide
                        $string61 = /Responder\.py/ nocase ascii wide
                        $string62 = /Responder\\Responder\.exe/ nocase ascii wide
                        $string63 = "ResponderConfigDump " nocase ascii wide
                        $string64 = /Responder\-Session\.log/ nocase ascii wide
                        $string65 = "Responder-Windows" nocase ascii wide
                        $string66 = /SMBRelay\.py/ nocase ascii wide
                        $string67 = "SpiderLabs/Responder" nocase ascii wide
                        $string68 = "wmic /interactive:off nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2" nocase ascii wide
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
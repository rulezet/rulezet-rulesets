rule legba
{
    meta:
        description = "Detection patterns for the tool 'legba' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "legba"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\-password\swordlists\/.{0,100}\.txt/ nocase ascii wide
                        $string2 = /\/legba\.git/ nocase ascii wide
                        $string3 = "/legba/target/release/legba"
                        $string4 = "/usr/bin/legba"
                        $string5 = "A fast multi protocol credential bruteforcer/sprayer/enumerator" nocase ascii wide
                        $string6 = /docker\sbuild\s\-t\slegba\s\./ nocase ascii wide
                        $string7 = "docker run legba" nocase ascii wide
                        $string8 = "evilsocket/legba" nocase ascii wide
                        $string9 = /evilsocket\@gmail\.com/ nocase ascii wide
                        $string10 = /legba\s.{0,100}\s\-\-username/ nocase ascii wide
                        $string11 = /legba\samqp\s.{0,100}\-\-target\s/ nocase ascii wide
                        $string12 = /legba\sdns\s.{0,100}\-\-data\s/ nocase ascii wide
                        $string13 = /legba\sftp\s.{0,100}\-\-target\s/ nocase ascii wide
                        $string14 = /legba\shttp\s.{0,100}\-\-http\-payload\s/ nocase ascii wide
                        $string15 = /legba\shttp\.basic\s.{0,100}\-\-target\s/ nocase ascii wide
                        $string16 = /legba\shttp\.enum\s.{0,100}\-\-http/ nocase ascii wide
                        $string17 = /legba\shttp\.ntlm1\s/ nocase ascii wide
                        $string18 = /legba\shttp\.ntlm2\s/ nocase ascii wide
                        $string19 = /legba\simap\s.{0,100}\-\-target\s/ nocase ascii wide
                        $string20 = /legba\skerberos\s.{0,100}\-\-target\s/ nocase ascii wide
                        $string21 = /legba\skerberos.{0,100}\-\-kerberos\-realm\s/ nocase ascii wide
                        $string22 = /legba\sldap\s.{0,100}\-\-ldap\-domain/ nocase ascii wide
                        $string23 = /legba\smongodb.{0,100}\s\-\-target\s/ nocase ascii wide
                        $string24 = /legba\smssql\s.{0,100}\s\-\-target\s/ nocase ascii wide
                        $string25 = /legba\smysql\s.{0,100}\s\-\-target\s/ nocase ascii wide
                        $string26 = /legba\spgsql\s.{0,100}\s\-\-target\s/ nocase ascii wide
                        $string27 = /legba\spop3\s.{0,100}\-\-target\s/ nocase ascii wide
                        $string28 = /legba\srdp\s.{0,100}\-\-target\s/ nocase ascii wide
                        $string29 = /legba\ssftp\s.{0,100}\-\-target\s/ nocase ascii wide
                        $string30 = /legba\ssmtp\s.{0,100}\-\-target\s/ nocase ascii wide
                        $string31 = /legba\sssh\s.{0,100}\-\-target\s/ nocase ascii wide
                        $string32 = /legba\sstomp\s.{0,100}\-\-target/ nocase ascii wide
                        $string33 = /legba\stelnet\s.{0,100}\-\-telnet\-/ nocase ascii wide
                        $string34 = /legba\svnc.{0,100}\s\-\-target\s/ nocase ascii wide
                        $string35 = /legba\-main\.zip/ nocase ascii wide
                        $string36 = "root cargo new --bin legba" nocase ascii wide
                        $string37 = /Simone\sMargaritelli\s\<evilsocket\@gmail\.com\>/ nocase ascii wide
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
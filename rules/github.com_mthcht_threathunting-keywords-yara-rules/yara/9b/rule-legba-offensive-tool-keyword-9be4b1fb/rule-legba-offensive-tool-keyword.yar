rule rule_legba_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'legba' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "legba"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_legba_offensive_tool_keyword = /\s\-\-password\swordlists\/.{0,100}\.txt/ nocase ascii wide
                        $string2_legba_offensive_tool_keyword = /\/legba\.git/ nocase ascii wide
                        $string3_legba_offensive_tool_keyword = "/legba/target/release/legba"
                        $string4_legba_offensive_tool_keyword = "/usr/bin/legba"
                        $string5_legba_offensive_tool_keyword = "A fast multi protocol credential bruteforcer/sprayer/enumerator" nocase ascii wide
                        $string6_legba_offensive_tool_keyword = /docker\sbuild\s\-t\slegba\s\./ nocase ascii wide
                        $string7_legba_offensive_tool_keyword = "docker run legba" nocase ascii wide
                        $string8_legba_offensive_tool_keyword = "evilsocket/legba" nocase ascii wide
                        $string9_legba_offensive_tool_keyword = /evilsocket\@gmail\.com/ nocase ascii wide
                        $string10_legba_offensive_tool_keyword = /legba\s.{0,100}\s\-\-username/ nocase ascii wide
                        $string11_legba_offensive_tool_keyword = /legba\samqp\s.{0,100}\-\-target\s/ nocase ascii wide
                        $string12_legba_offensive_tool_keyword = /legba\sdns\s.{0,100}\-\-data\s/ nocase ascii wide
                        $string13_legba_offensive_tool_keyword = /legba\sftp\s.{0,100}\-\-target\s/ nocase ascii wide
                        $string14_legba_offensive_tool_keyword = /legba\shttp\s.{0,100}\-\-http\-payload\s/ nocase ascii wide
                        $string15_legba_offensive_tool_keyword = /legba\shttp\.basic\s.{0,100}\-\-target\s/ nocase ascii wide
                        $string16_legba_offensive_tool_keyword = /legba\shttp\.enum\s.{0,100}\-\-http/ nocase ascii wide
                        $string17_legba_offensive_tool_keyword = /legba\shttp\.ntlm1\s/ nocase ascii wide
                        $string18_legba_offensive_tool_keyword = /legba\shttp\.ntlm2\s/ nocase ascii wide
                        $string19_legba_offensive_tool_keyword = /legba\simap\s.{0,100}\-\-target\s/ nocase ascii wide
                        $string20_legba_offensive_tool_keyword = /legba\skerberos\s.{0,100}\-\-target\s/ nocase ascii wide
                        $string21_legba_offensive_tool_keyword = /legba\skerberos.{0,100}\-\-kerberos\-realm\s/ nocase ascii wide
                        $string22_legba_offensive_tool_keyword = /legba\sldap\s.{0,100}\-\-ldap\-domain/ nocase ascii wide
                        $string23_legba_offensive_tool_keyword = /legba\smongodb.{0,100}\s\-\-target\s/ nocase ascii wide
                        $string24_legba_offensive_tool_keyword = /legba\smssql\s.{0,100}\s\-\-target\s/ nocase ascii wide
                        $string25_legba_offensive_tool_keyword = /legba\smysql\s.{0,100}\s\-\-target\s/ nocase ascii wide
                        $string26_legba_offensive_tool_keyword = /legba\spgsql\s.{0,100}\s\-\-target\s/ nocase ascii wide
                        $string27_legba_offensive_tool_keyword = /legba\spop3\s.{0,100}\-\-target\s/ nocase ascii wide
                        $string28_legba_offensive_tool_keyword = /legba\srdp\s.{0,100}\-\-target\s/ nocase ascii wide
                        $string29_legba_offensive_tool_keyword = /legba\ssftp\s.{0,100}\-\-target\s/ nocase ascii wide
                        $string30_legba_offensive_tool_keyword = /legba\ssmtp\s.{0,100}\-\-target\s/ nocase ascii wide
                        $string31_legba_offensive_tool_keyword = /legba\sssh\s.{0,100}\-\-target\s/ nocase ascii wide
                        $string32_legba_offensive_tool_keyword = /legba\sstomp\s.{0,100}\-\-target/ nocase ascii wide
                        $string33_legba_offensive_tool_keyword = /legba\stelnet\s.{0,100}\-\-telnet\-/ nocase ascii wide
                        $string34_legba_offensive_tool_keyword = /legba\svnc.{0,100}\s\-\-target\s/ nocase ascii wide
                        $string35_legba_offensive_tool_keyword = /legba\-main\.zip/ nocase ascii wide
                        $string36_legba_offensive_tool_keyword = "root cargo new --bin legba" nocase ascii wide
                        $string37_legba_offensive_tool_keyword = /Simone\sMargaritelli\s\<evilsocket\@gmail\.com\>/ nocase ascii wide
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
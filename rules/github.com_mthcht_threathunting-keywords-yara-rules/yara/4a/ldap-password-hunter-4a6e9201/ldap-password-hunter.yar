rule LDAP_Password_Hunter
{
    meta:
        description = "Detection patterns for the tool 'LDAP-Password-Hunter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LDAP-Password-Hunter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " FROM LDAPHUNTERFINDINGS" nocase ascii wide
                        $string2 = " INTO LDAPHUNTERFINDINGS" nocase ascii wide
                        $string3 = /\sldapph\.db/ nocase ascii wide
                        $string4 = /\/LDAP\-Password\-Hunter\.git/ nocase ascii wide
                        $string5 = /\/ldapph\.db/ nocase ascii wide
                        $string6 = /\\ldapph\.db/ nocase ascii wide
                        $string7 = "c850818a6b19486dae2a4c370797cbb4fa61a4ebd35cba8e94a60b54c4499c8b" nocase ascii wide
                        $string8 = /CREATE\sTABLE\s\[LDAPHUNTERFINDINGS\]/ nocase ascii wide
                        $string9 = "Creating a TGT ticket for the user" nocase ascii wide
                        $string10 = "DELETE FROM LDAPHUNTERFINDINGS" nocase ascii wide
                        $string11 = /getTGT\.py\s\-dc\-ip/ nocase ascii wide
                        $string12 = "INSERT INTO LDAPHUNTERFINDINGS " nocase ascii wide
                        $string13 = /kerberos\-ldap\-password\-hunter\.sh/ nocase ascii wide
                        $string14 = /kerberos\-ldap\-password\-hunter\.sh/ nocase ascii wide
                        $string15 = "LDAP PASSWORD ENUM" nocase ascii wide
                        $string16 = "LDAP PASSWORD HUNTER" nocase ascii wide
                        $string17 = /mv\s.{0,100}\.ccache\s.{0,100}\.ccache/ nocase ascii wide
                        $string18 = "oldboy21/LDAP-Password-Hunter" nocase ascii wide
                        $string19 = /password\|pwd\|creds\|cred\|secret\|userpw/ nocase ascii wide
                        $string20 = /Please\sbe\ssure\simpacket\sand\sldapsearch\sare\sinstalled\sand\syour\s\/etc\/krb5\.conf\sfile\sis\sclean/
                        $string21 = /Please\sbe\ssure\simpacket\sand\sldapsearch\sare\sinstalled\sand\syour\s\/etc\/krb5\.conf/
                        $string22 = "Please be sure impacket is installed in your system" nocase ascii wide
                        $string23 = "Please be sure impacket is installed in your system" nocase ascii wide
                        $string24 = /pwd\|creds\|cred\|secret\|userpw/ nocase ascii wide
                        $string25 = "Results are on disk, enumerating next DC!" nocase ascii wide
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
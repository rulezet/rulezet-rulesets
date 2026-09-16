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
                        $string17 = /mv\s.{0,1000}\.ccache\s.{0,1000}\.ccache/ nocase ascii wide
                        $string18 = "oldboy21/LDAP-Password-Hunter" nocase ascii wide
                        $string19 = /password\|pwd\|creds\|cred\|secret\|userpw/ nocase ascii wide
                        $string20 = /Please\sbe\ssure\simpacket\sand\sldapsearch\sare\sinstalled\sand\syour\s\/etc\/krb5\.conf\sfile\sis\sclean/
                        $string21 = /Please\sbe\ssure\simpacket\sand\sldapsearch\sare\sinstalled\sand\syour\s\/etc\/krb5\.conf/
                        $string22 = "Please be sure impacket is installed in your system" nocase ascii wide
                        $string23 = "Please be sure impacket is installed in your system" nocase ascii wide
                        $string24 = /pwd\|creds\|cred\|secret\|userpw/ nocase ascii wide
                        $string25 = "Results are on disk, enumerating next DC!" nocase ascii wide

    condition:
        any of them
}
rule smartbrute
{
    meta:
        description = "Detection patterns for the tool 'smartbrute' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smartbrute"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --bf-hashes-file " nocase ascii wide
                        $string2 = " --bf-passwords-file " nocase ascii wide
                        $string3 = " --ccache-ticket " nocase ascii wide
                        $string4 = " --neo4j-host " nocase ascii wide
                        $string5 = " -neo4j-password " nocase ascii wide
                        $string6 = " --neo4j-port " nocase ascii wide
                        $string7 = " --neo4j-user " nocase ascii wide
                        $string8 = /\/smartbrute\.git/ nocase ascii wide
                        $string9 = "/smartbrute-main"
                        $string10 = /\[bruteforce_mode\]/ nocase ascii wide
                        $string11 = /\\smartbrute\\/ nocase ascii wide
                        $string12 = /\\smartbrute\-main/ nocase ascii wide
                        $string13 = "52b07bced660711b3aa82b4cbf40156689045bcd695df40b1376c76e172beb8d" nocase ascii wide
                        $string14 = /Bad\spassword\scounts\sdont\sreplicate\sbetween\sdomain\scontrollers\.\sOnly\sthe\sPDC\sknows\sthe\sreal\samount\sof\sthose\.\sBe\ssure\sto\starget\sthe\sPDC\sso\sthat\saccounts\sdon\'t\sget\slocked\sout/ nocase ascii wide
                        $string15 = /bruteforce_attack\(/ nocase ascii wide
                        $string16 = "bruteforce_mode_kerberos_mode" nocase ascii wide
                        $string17 = "bruteforce_mode_ntlm_mode" nocase ascii wide
                        $string18 = /bruteforce_try_password_or_hash\(/ nocase ascii wide
                        $string19 = /bruteforce_try_user\(/ nocase ascii wide
                        $string20 = /docstring\sfor\sbruteforce\./ nocase ascii wide
                        $string21 = "Fetching domain information through a Kerberos auth over LDAP" nocase ascii wide
                        $string22 = "Fetching domain information through NTLM over LDAP" nocase ascii wide
                        $string23 = /options\.bruteforced_protocol/ nocase ascii wide
                        $string24 = "ShutdownRepo/smartbrute" nocase ascii wide
                        $string25 = /smart_try_password_or_hash\(/ nocase ascii wide
                        $string26 = "smartbrute%2520brute" nocase ascii wide
                        $string27 = /smartbrute\.py/ nocase ascii wide
                        $string28 = /smbrelayclient\.py/ nocase ascii wide
                        $string29 = "Starting bruteforce attack on " nocase ascii wide
                        $string30 = "The smart password spraying and bruteforcing tool for Active Directory Domain Services" nocase ascii wide

    condition:
        any of them
}
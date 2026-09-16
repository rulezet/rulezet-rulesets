rule t14m4t
{
    meta:
        description = "Detection patterns for the tool 't14m4t' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "t14m4t"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\/t14m4t\s/
                        $string2 = /Wordlist\/ftp_p\.txt/ nocase ascii wide
                        $string3 = /Wordlist\/ftp_u\.txt/ nocase ascii wide
                        $string4 = /Wordlist\/ftp_up\.txt/ nocase ascii wide
                        $string5 = /Wordlist\/mssql_up\.txt/ nocase ascii wide
                        $string6 = /Wordlist\/mysql_up\.txt/ nocase ascii wide
                        $string7 = /Wordlist\/oracle_up\.txt/ nocase ascii wide
                        $string8 = /Wordlist\/pass\.txt/ nocase ascii wide
                        $string9 = /Wordlist\/pop_p\.txt/ nocase ascii wide
                        $string10 = /Wordlist\/pop_u\.txt/ nocase ascii wide
                        $string11 = /Wordlist\/postgres_up\.txt/ nocase ascii wide
                        $string12 = /Wordlist\/smtp_p\.txt/ nocase ascii wide
                        $string13 = /Wordlist\/smtp_u\.txt/ nocase ascii wide
                        $string14 = /Wordlist\/snmp\.txt/ nocase ascii wide
                        $string15 = /Wordlist\/sql_p\.txt/ nocase ascii wide
                        $string16 = /Wordlist\/sql_u\.txt/ nocase ascii wide
                        $string17 = /Wordlist\/ssh_p\.txt/ nocase ascii wide
                        $string18 = /Wordlist\/ssh_u\.txt/ nocase ascii wide
                        $string19 = /Wordlist\/ssh_up\.txt/ nocase ascii wide
                        $string20 = /Wordlist\/telnet_p\.txt/ nocase ascii wide
                        $string21 = /Wordlist\/telnet_u\.txt/ nocase ascii wide
                        $string22 = /Wordlist\/telnet_up\.txt/ nocase ascii wide
                        $string23 = /Wordlist\/user\.txt/ nocase ascii wide
                        $string24 = /Wordlist\/vnc_p\.txt/ nocase ascii wide
                        $string25 = /Wordlist\/windows_u\.txt/ nocase ascii wide
                        $string26 = /Wordlist\/windows_up\.txt/ nocase ascii wide

    condition:
        any of them
}
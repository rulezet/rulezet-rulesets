rule rule_t14m4t_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 't14m4t' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "t14m4t"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_t14m4t_offensive_tool_keyword = /\.\/t14m4t\s/
                        $string2_t14m4t_offensive_tool_keyword = /Wordlist\/ftp_p\.txt/ nocase ascii wide
                        $string3_t14m4t_offensive_tool_keyword = /Wordlist\/ftp_u\.txt/ nocase ascii wide
                        $string4_t14m4t_offensive_tool_keyword = /Wordlist\/ftp_up\.txt/ nocase ascii wide
                        $string5_t14m4t_offensive_tool_keyword = /Wordlist\/mssql_up\.txt/ nocase ascii wide
                        $string6_t14m4t_offensive_tool_keyword = /Wordlist\/mysql_up\.txt/ nocase ascii wide
                        $string7_t14m4t_offensive_tool_keyword = /Wordlist\/oracle_up\.txt/ nocase ascii wide
                        $string8_t14m4t_offensive_tool_keyword = /Wordlist\/pass\.txt/ nocase ascii wide
                        $string9_t14m4t_offensive_tool_keyword = /Wordlist\/pop_p\.txt/ nocase ascii wide
                        $string10_t14m4t_offensive_tool_keyword = /Wordlist\/pop_u\.txt/ nocase ascii wide
                        $string11_t14m4t_offensive_tool_keyword = /Wordlist\/postgres_up\.txt/ nocase ascii wide
                        $string12_t14m4t_offensive_tool_keyword = /Wordlist\/smtp_p\.txt/ nocase ascii wide
                        $string13_t14m4t_offensive_tool_keyword = /Wordlist\/smtp_u\.txt/ nocase ascii wide
                        $string14_t14m4t_offensive_tool_keyword = /Wordlist\/snmp\.txt/ nocase ascii wide
                        $string15_t14m4t_offensive_tool_keyword = /Wordlist\/sql_p\.txt/ nocase ascii wide
                        $string16_t14m4t_offensive_tool_keyword = /Wordlist\/sql_u\.txt/ nocase ascii wide
                        $string17_t14m4t_offensive_tool_keyword = /Wordlist\/ssh_p\.txt/ nocase ascii wide
                        $string18_t14m4t_offensive_tool_keyword = /Wordlist\/ssh_u\.txt/ nocase ascii wide
                        $string19_t14m4t_offensive_tool_keyword = /Wordlist\/ssh_up\.txt/ nocase ascii wide
                        $string20_t14m4t_offensive_tool_keyword = /Wordlist\/telnet_p\.txt/ nocase ascii wide
                        $string21_t14m4t_offensive_tool_keyword = /Wordlist\/telnet_u\.txt/ nocase ascii wide
                        $string22_t14m4t_offensive_tool_keyword = /Wordlist\/telnet_up\.txt/ nocase ascii wide
                        $string23_t14m4t_offensive_tool_keyword = /Wordlist\/user\.txt/ nocase ascii wide
                        $string24_t14m4t_offensive_tool_keyword = /Wordlist\/vnc_p\.txt/ nocase ascii wide
                        $string25_t14m4t_offensive_tool_keyword = /Wordlist\/windows_u\.txt/ nocase ascii wide
                        $string26_t14m4t_offensive_tool_keyword = /Wordlist\/windows_up\.txt/ nocase ascii wide

    condition:
        any of them
}
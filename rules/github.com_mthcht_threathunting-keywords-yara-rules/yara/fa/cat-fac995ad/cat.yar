rule cat
{
    meta:
        description = "Detection patterns for the tool 'cat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cat"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /cat\s.{0,1000}\.atftp_history/ nocase ascii wide
                        $string2 = /cat\s.{0,1000}\.atftp_history/ nocase ascii wide
                        $string3 = /cat\s.{0,1000}\.bash_history/
                        $string4 = /cat\s.{0,1000}\.bash_history/
                        $string5 = /cat\s.{0,1000}\.mysql_history/ nocase ascii wide
                        $string6 = /cat\s.{0,1000}\.mysql_history/ nocase ascii wide
                        $string7 = /cat\s.{0,1000}\.nano_history/ nocase ascii wide
                        $string8 = /cat\s.{0,1000}\.nano_history/ nocase ascii wide
                        $string9 = /cat\s.{0,1000}\.php_history/ nocase ascii wide
                        $string10 = /cat\s.{0,1000}\.php_history/ nocase ascii wide
                        $string11 = /cat\s.{0,1000}\.zsh_history/ nocase ascii wide
                        $string12 = /cat\s.{0,1000}\.zsh_history/ nocase ascii wide
                        $string13 = /cat\s.{0,1000}bash\-history/
                        $string14 = /cat\s\/dev\/null\s\>\s\$HISTFILE/ nocase ascii wide
                        $string15 = /cat\s\/dev\/null\s\>\s\/var\/log\/.{0,1000}\.log/
                        $string16 = /cat\s\/dev\/null\s\>\s\/var\/log\/auth\.log/
                        $string17 = "cat /dev/null > /var/log/messages"
                        $string18 = /cat\s\/dev\/null\s\>\s\~\/\.bash_history/
                        $string19 = "cat /dev/zero > /var/lol/messages"
                        $string20 = "cat /etc/passwd"
                        $string21 = "cat /etc/shadow"
                        $string22 = "cat /etc/sudoers"
                        $string23 = /cat\s\/root\/\.aws\/credentials/ nocase ascii wide
                        $string24 = /cat\s\/root\/\.ssh\/id_rsa/ nocase ascii wide

    condition:
        any of them
}
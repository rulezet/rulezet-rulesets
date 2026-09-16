rule rule_cat_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'cat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cat"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_cat_greyware_tool_keyword = /cat\s.{0,1000}\.atftp_history/ nocase ascii wide
                        $string2_cat_greyware_tool_keyword = /cat\s.{0,1000}\.atftp_history/ nocase ascii wide
                        $string3_cat_greyware_tool_keyword = /cat\s.{0,1000}\.bash_history/
                        $string4_cat_greyware_tool_keyword = /cat\s.{0,1000}\.bash_history/
                        $string5_cat_greyware_tool_keyword = /cat\s.{0,1000}\.mysql_history/ nocase ascii wide
                        $string6_cat_greyware_tool_keyword = /cat\s.{0,1000}\.mysql_history/ nocase ascii wide
                        $string7_cat_greyware_tool_keyword = /cat\s.{0,1000}\.nano_history/ nocase ascii wide
                        $string8_cat_greyware_tool_keyword = /cat\s.{0,1000}\.nano_history/ nocase ascii wide
                        $string9_cat_greyware_tool_keyword = /cat\s.{0,1000}\.php_history/ nocase ascii wide
                        $string10_cat_greyware_tool_keyword = /cat\s.{0,1000}\.php_history/ nocase ascii wide
                        $string11_cat_greyware_tool_keyword = /cat\s.{0,1000}\.zsh_history/ nocase ascii wide
                        $string12_cat_greyware_tool_keyword = /cat\s.{0,1000}\.zsh_history/ nocase ascii wide
                        $string13_cat_greyware_tool_keyword = /cat\s.{0,1000}bash\-history/
                        $string14_cat_greyware_tool_keyword = /cat\s\/dev\/null\s\>\s\$HISTFILE/ nocase ascii wide
                        $string15_cat_greyware_tool_keyword = /cat\s\/dev\/null\s\>\s\/var\/log\/.{0,1000}\.log/
                        $string16_cat_greyware_tool_keyword = /cat\s\/dev\/null\s\>\s\/var\/log\/auth\.log/
                        $string17_cat_greyware_tool_keyword = "cat /dev/null > /var/log/messages"
                        $string18_cat_greyware_tool_keyword = /cat\s\/dev\/null\s\>\s\~\/\.bash_history/
                        $string19_cat_greyware_tool_keyword = "cat /dev/zero > /var/lol/messages"
                        $string20_cat_greyware_tool_keyword = "cat /etc/passwd"
                        $string21_cat_greyware_tool_keyword = "cat /etc/shadow"
                        $string22_cat_greyware_tool_keyword = "cat /etc/sudoers"
                        $string23_cat_greyware_tool_keyword = /cat\s\/root\/\.aws\/credentials/ nocase ascii wide
                        $string24_cat_greyware_tool_keyword = /cat\s\/root\/\.ssh\/id_rsa/ nocase ascii wide

    condition:
        any of them
}
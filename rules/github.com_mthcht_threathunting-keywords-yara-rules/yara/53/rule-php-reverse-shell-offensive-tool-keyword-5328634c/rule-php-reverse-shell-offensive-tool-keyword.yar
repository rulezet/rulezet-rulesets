rule rule_php_reverse_shell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'php-reverse-shell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "php-reverse-shell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_php_reverse_shell_offensive_tool_keyword = /\snew\sSh\(\'127\.0\.0\.1\'\,9000\)/ nocase ascii wide
                        $string2_php_reverse_shell_offensive_tool_keyword = /\/php_reverse_shell\.php/ nocase ascii wide
                        $string3_php_reverse_shell_offensive_tool_keyword = /\/php\-reverse\-shell\.git/ nocase ascii wide
                        $string4_php_reverse_shell_offensive_tool_keyword = "/php-reverse-shell/releases/" nocase ascii wide
                        $string5_php_reverse_shell_offensive_tool_keyword = "/php-reverse-shell/zipball/" nocase ascii wide
                        $string6_php_reverse_shell_offensive_tool_keyword = "009e013613ce6435e4a83fadf560f9b19e3adbb774ae2d7daab7fef6e6bd586d" nocase ascii wide
                        $string7_php_reverse_shell_offensive_tool_keyword = "00e574776767b1adaccff7b62bdb544633c806d5bde00c267edbcd3459e23d89" nocase ascii wide
                        $string8_php_reverse_shell_offensive_tool_keyword = "12eb25ef52882b1d26acfcdd8eedc223874bcc405be27cc669fa655f2564c64e" nocase ascii wide
                        $string9_php_reverse_shell_offensive_tool_keyword = "3ee55b131560263d8f4d9a971e7a82e07b9b80db67fd9496ba2d2b0aeeaa2759" nocase ascii wide
                        $string10_php_reverse_shell_offensive_tool_keyword = "64ce94651ee719279668c5d3bcfb376da9993aba306dc8b7f1e4def4c6917312" nocase ascii wide
                        $string11_php_reverse_shell_offensive_tool_keyword = "6727e1988ae996df818696de98826a6dcf0e0fc3dd7e32cf9247b41fa225b856" nocase ascii wide
                        $string12_php_reverse_shell_offensive_tool_keyword = "8596bb9703901bd2b0174aa550288f303e26f27d72a26daff201e7ea709da002" nocase ascii wide
                        $string13_php_reverse_shell_offensive_tool_keyword = "94fcbb0aadcaaeae36a043eee19005e3e6ae2c991a389291fef7d4ecbe68aeb5" nocase ascii wide
                        $string14_php_reverse_shell_offensive_tool_keyword = "ab574153b5e7f7bef16f38ab53fcb107e2b1459426a73acf6fdd41434c94fa94" nocase ascii wide
                        $string15_php_reverse_shell_offensive_tool_keyword = "c949913be70a42e2ea9395d2a2e7ac427cdc0d756b6b12d1e607ba3e11937e35" nocase ascii wide
                        $string16_php_reverse_shell_offensive_tool_keyword = "ca3560757b7667c3b9ac2cca3b586493ef266b2b0591c1252d35f9e3a39cad08" nocase ascii wide
                        $string17_php_reverse_shell_offensive_tool_keyword = "d28ac4233d53079b9f57c3dd15c024feaaffd407b26568da298c87c5d563c60c" nocase ascii wide
                        $string18_php_reverse_shell_offensive_tool_keyword = "ivan-sincek/php-reverse-shell" nocase ascii wide
                        $string19_php_reverse_shell_offensive_tool_keyword = /new\sShell\(\'127\.0\.0\.1\'\,\s9000\)/ nocase ascii wide
                        $string20_php_reverse_shell_offensive_tool_keyword = /php_reverse_shell_mini\.php/ nocase ascii wide
                        $string21_php_reverse_shell_offensive_tool_keyword = /php_reverse_shell_older\.php/ nocase ascii wide
                        $string22_php_reverse_shell_offensive_tool_keyword = /php_reverse_shell_older_mini\.php/ nocase ascii wide
                        $string23_php_reverse_shell_offensive_tool_keyword = /simple_php_web_shell_get\.php/ nocase ascii wide
                        $string24_php_reverse_shell_offensive_tool_keyword = /simple_php_web_shell_get\.php/ nocase ascii wide
                        $string25_php_reverse_shell_offensive_tool_keyword = /simple_php_web_shell_get__mini_v2\.php/ nocase ascii wide
                        $string26_php_reverse_shell_offensive_tool_keyword = /simple_php_web_shell_get_mini\.php/ nocase ascii wide
                        $string27_php_reverse_shell_offensive_tool_keyword = /simple_php_web_shell_get_v2\.php/ nocase ascii wide
                        $string28_php_reverse_shell_offensive_tool_keyword = /simple_php_web_shell_get_v2\.php/ nocase ascii wide
                        $string29_php_reverse_shell_offensive_tool_keyword = /simple_php_web_shell_post\.php/ nocase ascii wide
                        $string30_php_reverse_shell_offensive_tool_keyword = /simple_php_web_shell_post_mini\.php/ nocase ascii wide

    condition:
        any of them
}
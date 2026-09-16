rule rule_cat_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'cat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cat"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_cat_greyware_tool_keyword = /cat\s.{0,100}\.atftp_history/ nocase ascii wide
                        $string2_cat_greyware_tool_keyword = /cat\s.{0,100}\.atftp_history/ nocase ascii wide
                        $string3_cat_greyware_tool_keyword = /cat\s.{0,100}\.bash_history/
                        $string4_cat_greyware_tool_keyword = /cat\s.{0,100}\.bash_history/
                        $string5_cat_greyware_tool_keyword = /cat\s.{0,100}\.mysql_history/ nocase ascii wide
                        $string6_cat_greyware_tool_keyword = /cat\s.{0,100}\.mysql_history/ nocase ascii wide
                        $string7_cat_greyware_tool_keyword = /cat\s.{0,100}\.nano_history/ nocase ascii wide
                        $string8_cat_greyware_tool_keyword = /cat\s.{0,100}\.nano_history/ nocase ascii wide
                        $string9_cat_greyware_tool_keyword = /cat\s.{0,100}\.php_history/ nocase ascii wide
                        $string10_cat_greyware_tool_keyword = /cat\s.{0,100}\.php_history/ nocase ascii wide
                        $string11_cat_greyware_tool_keyword = /cat\s.{0,100}\.zsh_history/ nocase ascii wide
                        $string12_cat_greyware_tool_keyword = /cat\s.{0,100}\.zsh_history/ nocase ascii wide
                        $string13_cat_greyware_tool_keyword = /cat\s.{0,100}bash\-history/
                        $string14_cat_greyware_tool_keyword = /cat\s\/dev\/null\s\>\s\$HISTFILE/ nocase ascii wide
                        $string15_cat_greyware_tool_keyword = /cat\s\/dev\/null\s\>\s\/var\/log\/.{0,100}\.log/
                        $string16_cat_greyware_tool_keyword = /cat\s\/dev\/null\s\>\s\/var\/log\/auth\.log/
                        $string17_cat_greyware_tool_keyword = "cat /dev/null > /var/log/messages"
                        $string18_cat_greyware_tool_keyword = /cat\s\/dev\/null\s\>\s\~\/\.bash_history/
                        $string19_cat_greyware_tool_keyword = "cat /dev/zero > /var/lol/messages"
                        $string20_cat_greyware_tool_keyword = "cat /etc/passwd"
                        $string21_cat_greyware_tool_keyword = "cat /etc/shadow"
                        $string22_cat_greyware_tool_keyword = "cat /etc/sudoers"
                        $string23_cat_greyware_tool_keyword = /cat\s\/root\/\.aws\/credentials/ nocase ascii wide
                        $string24_cat_greyware_tool_keyword = /cat\s\/root\/\.ssh\/id_rsa/ nocase ascii wide
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
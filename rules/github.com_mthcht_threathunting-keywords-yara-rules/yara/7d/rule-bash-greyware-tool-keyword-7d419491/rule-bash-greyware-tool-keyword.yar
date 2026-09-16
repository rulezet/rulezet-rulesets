rule rule_bash_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bash' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bash"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_bash_greyware_tool_keyword = " > /var/log/syslog"
                        $string2_bash_greyware_tool_keyword = " >/var/log/syslog"
                        $string3_bash_greyware_tool_keyword = /\.bash_history\s\>\/dev\/null\s2\>\&1/ nocase ascii wide
                        $string4_bash_greyware_tool_keyword = ": > /var/log/messages"
                        $string5_bash_greyware_tool_keyword = ": > /var/spool/mail/"
                        $string6_bash_greyware_tool_keyword = /bash\s\-c\s.{0,100}curl\s.{0,100}\.sh\s\|\sbash/
                        $string7_bash_greyware_tool_keyword = /bash\s\-c\s.{0,100}wget\s.{0,100}\.sh\s\|\sbash/
                        $string8_bash_greyware_tool_keyword = "bash -c 'bash -i >& /dev/tcp/" nocase ascii wide
                        $string9_bash_greyware_tool_keyword = /bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,100}\/.{0,100}\s0\>\&1/
                        $string10_bash_greyware_tool_keyword = /bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,100}\/.{0,100}\s0\>\&1/
                        $string11_bash_greyware_tool_keyword = /cat\s\/dev\/null\s\>\s.{0,100}bash_history/
                        $string12_bash_greyware_tool_keyword = /echo\s.{0,100}\s\.bash_history/
                        $string13_bash_greyware_tool_keyword = /echo\s.{0,100}\s\/home\/.{0,100}\/\.bash_history/
                        $string14_bash_greyware_tool_keyword = /echo\s.{0,100}\s\/root\/\.bash_history/
                        $string15_bash_greyware_tool_keyword = /echo\s.{0,100}\:\:0\:0\:\:\/root\:\/bin\/bash.{0,100}\s\>\>\/etc\/passwd/
                        $string16_bash_greyware_tool_keyword = /echo\s.{0,100}APT\:\:Update\:\:Pre\-Invoke\s.{0,100}nohup\sncat\s\-lvp\s.{0,100}\s\-e\s\/bin\/bash\s.{0,100}\s\>\s\/etc\/apt\/apt\.conf\.d\//
                        $string17_bash_greyware_tool_keyword = /echo\s.{0,100}bash\s\-c\s.{0,100}bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,100}\/.{0,100}\s\>\>\s\/etc\/update\-motd\.d\/00\-header/
                        $string18_bash_greyware_tool_keyword = /exec\s\/bin\/sh\s0\<\/dev\/tcp\/.{0,100}\/.{0,100}1\>\&0\s2\>\&0/
                        $string19_bash_greyware_tool_keyword = /exec\s5\<\>\/dev\/tcp\/.{0,100}\/.{0,100}.{0,100}cat\s\<\&5\s\|\swhile\sread\sline.{0,100}\sdo\s\$line\s2\>\&5\s\>\&5.{0,100}\sdone/
                        $string20_bash_greyware_tool_keyword = "export HISTFILE=/dev/null"
                        $string21_bash_greyware_tool_keyword = "export HISTFILESIZE=0"
                        $string22_bash_greyware_tool_keyword = "export HISTFILESIZE=0"
                        $string23_bash_greyware_tool_keyword = "HISTCONTROL=ignoredups:ignorespace"
                        $string24_bash_greyware_tool_keyword = "history -c"
                        $string25_bash_greyware_tool_keyword = "HISTORY=/dev/null"
                        $string26_bash_greyware_tool_keyword = /ln\s\-sf\s\/dev\/null\s.{0,100}bash_history/
                        $string27_bash_greyware_tool_keyword = /PROMPT_COMMAND\=.{0,100}history\s\-a.{0,100}\stail\s.{0,100}\.bash_history\s\>\s\/dev\/tcp\/127\.0\.0\.1\//
                        $string28_bash_greyware_tool_keyword = /rm\s\.bash_history/
                        $string29_bash_greyware_tool_keyword = /rm\s\/home\/.{0,100}\/\.bash_history/
                        $string30_bash_greyware_tool_keyword = /rm\s\/root\/\.bash_history/
                        $string31_bash_greyware_tool_keyword = /set\shistory\s\+o/
                        $string32_bash_greyware_tool_keyword = /sh\s\>\/dev\/tcp\/.{0,100}\s\<\&1\s2\>\&1/
                        $string33_bash_greyware_tool_keyword = /sh\s\-i\s\>\&\s\/dev\/udp\/.{0,100}\/.{0,100}\s0\>\&1/
                        $string34_bash_greyware_tool_keyword = /truncate\s\-s0\s.{0,100}bash_history\'/
                        $string35_bash_greyware_tool_keyword = "unset HISTFILE"
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
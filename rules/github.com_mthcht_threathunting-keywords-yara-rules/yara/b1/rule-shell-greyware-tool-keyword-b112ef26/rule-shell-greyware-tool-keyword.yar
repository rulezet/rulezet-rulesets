rule rule_shell_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'shell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shell"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_shell_greyware_tool_keyword = /\/bin\/sh\s\|\snc/
                        $string2_shell_greyware_tool_keyword = "/bin/sh -i <&3 >&3 2>&3"
                        $string3_shell_greyware_tool_keyword = /rm\s\-f\sbackpipe.{0,100}\smknod\s\/tmp\/backpipe\sp\s\&\&\snc\s/ nocase ascii wide
                        $string4_shell_greyware_tool_keyword = "sc config WinDefend start= disabled" nocase ascii wide
                        $string5_shell_greyware_tool_keyword = "schkconfig off cbdaemon" nocase ascii wide
                        $string6_shell_greyware_tool_keyword = "service cbdaemon stop" nocase ascii wide
                        $string7_shell_greyware_tool_keyword = /socket\(S.{0,100}PF_INET.{0,100}SOCK_STREAM.{0,100}getprotobyname\(.{0,100}tcp.{0,100}\)\).{0,100}if\(connect\(S.{0,100}sockaddr_in\(\$p.{0,100}inet_aton\(\$i\)\)\)\)/ nocase ascii wide
                        $string8_shell_greyware_tool_keyword = /STDIN\-\>fdopen\(\$c.{0,100}r\).{0,100}\$\~\-\>fdopen\(\$c.{0,100}w\).{0,100}system\$_\swhile\<\>/ nocase ascii wide
                        $string9_shell_greyware_tool_keyword = /uname\s\-a.{0,100}\sw.{0,100}\sid.{0,100}\s\/bin\/bash\s\-i/
                        $string10_shell_greyware_tool_keyword = "setenforce 0"
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
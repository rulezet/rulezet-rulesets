rule Villain
{
    meta:
        description = "Detection patterns for the tool 'Villain' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Villain"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --file-smuggler-port "
                        $string2 = " --hoax-port "
                        $string3 = " --netcat-port "
                        $string4 = /\.villain_core/
                        $string5 = /\/hoaxshell\/.{0,100}\.py/
                        $string6 = "/t3l3machus/Villain"
                        $string7 = /\/villain\.py/
                        $string8 = /\\hoaxshell\\.{0,100}\.py/
                        $string9 = /awk_reverse_tcp\.py/
                        $string10 = /bash_read_line_reverse_tcp\.py/
                        $string11 = "cmdinspector OFF"
                        $string12 = "cmdinspector ON"
                        $string13 = "conptyshell "
                        $string14 = "eRv6yTYhShell"
                        $string15 = "File_Smuggler_Http_Handler"
                        $string16 = "generate payload="
                        $string17 = "Invoke-ConPtyShell"
                        $string18 = "list_backdoors"
                        $string19 = "obfuscate_cmdlet"
                        $string20 = /perl_no_sh_reverse_tcp\.py/
                        $string21 = /php_passthru_reverse_tcp\.py/
                        $string22 = /php_popen_reverse_tcp\.py/
                        $string23 = /php_proc_open_reverse_tcp\.py/
                        $string24 = /powershell_reverse_tcp\.py/
                        $string25 = /powershell_reverse_tcp_v2\.py/
                        $string26 = "proxy_cmd_for_exec_by_sibling"
                        $string27 = /python3_reverse_tcp\.py/
                        $string28 = /python3_reverse_tcp_v2\.py/
                        $string29 = /ruby_no_sh_reverse_tcp\.py/
                        $string30 = /ruby_reverse_tcp\.py/
                        $string31 = "SpawneRv6yTYhShell"
                        $string32 = /Villain\.git/
                        $string33 = "Villain/Core"
                        $string34 = /villain_core\.py/
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
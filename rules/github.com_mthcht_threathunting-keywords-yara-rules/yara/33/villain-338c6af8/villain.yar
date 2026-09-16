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
                        $string5 = /\/hoaxshell\/.{0,1000}\.py/
                        $string6 = "/t3l3machus/Villain"
                        $string7 = /\/villain\.py/
                        $string8 = /\\hoaxshell\\.{0,1000}\.py/
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

    condition:
        any of them
}
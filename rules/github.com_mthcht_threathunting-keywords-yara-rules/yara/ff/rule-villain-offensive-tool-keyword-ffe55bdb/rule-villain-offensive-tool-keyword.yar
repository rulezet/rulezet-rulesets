rule rule_Villain_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Villain' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Villain"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Villain_offensive_tool_keyword = " --file-smuggler-port "
                        $string2_Villain_offensive_tool_keyword = " --hoax-port "
                        $string3_Villain_offensive_tool_keyword = " --netcat-port "
                        $string4_Villain_offensive_tool_keyword = /\.villain_core/
                        $string5_Villain_offensive_tool_keyword = /\/hoaxshell\/.{0,1000}\.py/
                        $string6_Villain_offensive_tool_keyword = "/t3l3machus/Villain"
                        $string7_Villain_offensive_tool_keyword = /\/villain\.py/
                        $string8_Villain_offensive_tool_keyword = /\\hoaxshell\\.{0,1000}\.py/
                        $string9_Villain_offensive_tool_keyword = /awk_reverse_tcp\.py/
                        $string10_Villain_offensive_tool_keyword = /bash_read_line_reverse_tcp\.py/
                        $string11_Villain_offensive_tool_keyword = "cmdinspector OFF"
                        $string12_Villain_offensive_tool_keyword = "cmdinspector ON"
                        $string13_Villain_offensive_tool_keyword = "conptyshell "
                        $string14_Villain_offensive_tool_keyword = "eRv6yTYhShell"
                        $string15_Villain_offensive_tool_keyword = "File_Smuggler_Http_Handler"
                        $string16_Villain_offensive_tool_keyword = "generate payload="
                        $string17_Villain_offensive_tool_keyword = "Invoke-ConPtyShell"
                        $string18_Villain_offensive_tool_keyword = "list_backdoors"
                        $string19_Villain_offensive_tool_keyword = "obfuscate_cmdlet"
                        $string20_Villain_offensive_tool_keyword = /perl_no_sh_reverse_tcp\.py/
                        $string21_Villain_offensive_tool_keyword = /php_passthru_reverse_tcp\.py/
                        $string22_Villain_offensive_tool_keyword = /php_popen_reverse_tcp\.py/
                        $string23_Villain_offensive_tool_keyword = /php_proc_open_reverse_tcp\.py/
                        $string24_Villain_offensive_tool_keyword = /powershell_reverse_tcp\.py/
                        $string25_Villain_offensive_tool_keyword = /powershell_reverse_tcp_v2\.py/
                        $string26_Villain_offensive_tool_keyword = "proxy_cmd_for_exec_by_sibling"
                        $string27_Villain_offensive_tool_keyword = /python3_reverse_tcp\.py/
                        $string28_Villain_offensive_tool_keyword = /python3_reverse_tcp_v2\.py/
                        $string29_Villain_offensive_tool_keyword = /ruby_no_sh_reverse_tcp\.py/
                        $string30_Villain_offensive_tool_keyword = /ruby_reverse_tcp\.py/
                        $string31_Villain_offensive_tool_keyword = "SpawneRv6yTYhShell"
                        $string32_Villain_offensive_tool_keyword = /Villain\.git/
                        $string33_Villain_offensive_tool_keyword = "Villain/Core"
                        $string34_Villain_offensive_tool_keyword = /villain_core\.py/

    condition:
        any of them
}
rule rule_TripleCross_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TripleCross' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TripleCross"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_TripleCross_offensive_tool_keyword = " CC_TRIGGER_SYN_PACKET_KEY_3_ENCRYPTED_SHELL"
                        $string2_TripleCross_offensive_tool_keyword = " received ACK from backdoor"
                        $string3_TripleCross_offensive_tool_keyword = /\.\/injector\s\-/
                        $string4_TripleCross_offensive_tool_keyword = /\/etc\/cron\.d\/ebpfbackdoor/
                        $string5_TripleCross_offensive_tool_keyword = /\/etc\/sudoers\.d\/ebpfbackdoor/
                        $string6_TripleCross_offensive_tool_keyword = "/execve_hijack"
                        $string7_TripleCross_offensive_tool_keyword = /\/injection_lib\.so/
                        $string8_TripleCross_offensive_tool_keyword = /\/src\/common\/c\&c\.h/
                        $string9_TripleCross_offensive_tool_keyword = "/TFG/src/helpers/execve_hijack"
                        $string10_TripleCross_offensive_tool_keyword = /\/TripleCross\.git/
                        $string11_TripleCross_offensive_tool_keyword = "/TripleCross/apps/"
                        $string12_TripleCross_offensive_tool_keyword = /\/TripleCross\-0\.1\.0\.zip/
                        $string13_TripleCross_offensive_tool_keyword = /\/TripleCross\-0\.1\.0\//
                        $string14_TripleCross_offensive_tool_keyword = /\>\>\sWhere\sto\shide\sthe\spayload\?\sSelect\sa\snumber\:\s/
                        $string15_TripleCross_offensive_tool_keyword = "Activate all of rootkit's hooks"
                        $string16_TripleCross_offensive_tool_keyword = /activate_command_control_shell\(/
                        $string17_TripleCross_offensive_tool_keyword = /activate_command_control_shell_encrypted\(/
                        $string18_TripleCross_offensive_tool_keyword = "Activated COMMAND & CONTROL encrypted shell"
                        $string19_TripleCross_offensive_tool_keyword = "Activated COMMAND & CONTROL shell"
                        $string20_TripleCross_offensive_tool_keyword = "Activating COMMAND & CONTROL with MULTI-PACKET backdoor trigger"
                        $string21_TripleCross_offensive_tool_keyword = "Backdoor did not understand the request"
                        $string22_TripleCross_offensive_tool_keyword = "Backdoor sent unrecognizable message:"
                        $string23_TripleCross_offensive_tool_keyword = "Crafting malicious SYN packet"
                        $string24_TripleCross_offensive_tool_keyword = "Detected possible phantom shell command"
                        $string25_TripleCross_offensive_tool_keyword = "h3xduck/TripleCross"
                        $string26_TripleCross_offensive_tool_keyword = "Libbpf-powered rootkit"
                        $string27_TripleCross_offensive_tool_keyword = "Malicious program execve hijacker executed"
                        $string28_TripleCross_offensive_tool_keyword = "PATH_EXECUTION_HIJACK_PROGRAM"
                        $string29_TripleCross_offensive_tool_keyword = "Rootkit is already installed"
                        $string30_TripleCross_offensive_tool_keyword = "Running hijacking process"
                        $string31_TripleCross_offensive_tool_keyword = "Sending malicious packet to infected machine"
                        $string32_TripleCross_offensive_tool_keyword = "Sending malicious packet to infected machine"
                        $string33_TripleCross_offensive_tool_keyword = "Spawn a phantom shell - with pattern-based trigger"
                        $string34_TripleCross_offensive_tool_keyword = "Spawn encrypted pseudo-shell with IP - with "
                        $string35_TripleCross_offensive_tool_keyword = "Spawn plaintext pseudo-shell with IP - using "
                        $string36_TripleCross_offensive_tool_keyword = /The\sbackdoor\sjust\ssignaled\san\sACK\.\sThis\sshould\snot\shave\shappened/
                        $string37_TripleCross_offensive_tool_keyword = "Waiting for rootkit response"
                        $string38_TripleCross_offensive_tool_keyword = /xdp\/backdoor\.h/

    condition:
        any of them
}
rule TripleCross
{
    meta:
        description = "Detection patterns for the tool 'TripleCross' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TripleCross"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " CC_TRIGGER_SYN_PACKET_KEY_3_ENCRYPTED_SHELL"
                        $string2 = " received ACK from backdoor"
                        $string3 = /\.\/injector\s\-/
                        $string4 = /\/etc\/cron\.d\/ebpfbackdoor/
                        $string5 = /\/etc\/sudoers\.d\/ebpfbackdoor/
                        $string6 = "/execve_hijack"
                        $string7 = /\/injection_lib\.so/
                        $string8 = /\/src\/common\/c\&c\.h/
                        $string9 = "/TFG/src/helpers/execve_hijack"
                        $string10 = /\/TripleCross\.git/
                        $string11 = "/TripleCross/apps/"
                        $string12 = /\/TripleCross\-0\.1\.0\.zip/
                        $string13 = /\/TripleCross\-0\.1\.0\//
                        $string14 = /\>\>\sWhere\sto\shide\sthe\spayload\?\sSelect\sa\snumber\:\s/
                        $string15 = "Activate all of rootkit's hooks"
                        $string16 = /activate_command_control_shell\(/
                        $string17 = /activate_command_control_shell_encrypted\(/
                        $string18 = "Activated COMMAND & CONTROL encrypted shell"
                        $string19 = "Activated COMMAND & CONTROL shell"
                        $string20 = "Activating COMMAND & CONTROL with MULTI-PACKET backdoor trigger"
                        $string21 = "Backdoor did not understand the request"
                        $string22 = "Backdoor sent unrecognizable message:"
                        $string23 = "Crafting malicious SYN packet"
                        $string24 = "Detected possible phantom shell command"
                        $string25 = "h3xduck/TripleCross"
                        $string26 = "Libbpf-powered rootkit"
                        $string27 = "Malicious program execve hijacker executed"
                        $string28 = "PATH_EXECUTION_HIJACK_PROGRAM"
                        $string29 = "Rootkit is already installed"
                        $string30 = "Running hijacking process"
                        $string31 = "Sending malicious packet to infected machine"
                        $string32 = "Sending malicious packet to infected machine"
                        $string33 = "Spawn a phantom shell - with pattern-based trigger"
                        $string34 = "Spawn encrypted pseudo-shell with IP - with "
                        $string35 = "Spawn plaintext pseudo-shell with IP - using "
                        $string36 = /The\sbackdoor\sjust\ssignaled\san\sACK\.\sThis\sshould\snot\shave\shappened/
                        $string37 = "Waiting for rootkit response"
                        $string38 = /xdp\/backdoor\.h/
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
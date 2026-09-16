rule monkey
{
    meta:
        description = "Detection patterns for the tool 'monkey' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "monkey"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\/monkey\.sh/
                        $string2 = "/infection_monkey/" nocase ascii wide
                        $string3 = /\/log4shell\.py/ nocase ascii wide
                        $string4 = /\/monkey\.py/ nocase ascii wide
                        $string5 = /\/monkey_island\.py/ nocase ascii wide
                        $string6 = /\/shellshock\.py/ nocase ascii wide
                        $string7 = /\/smbexec\.py/ nocase ascii wide
                        $string8 = /\/timestomping\.ps1/ nocase ascii wide
                        $string9 = /\/trap_command\.py/ nocase ascii wide
                        $string10 = /\/web_rce\.py/ nocase ascii wide
                        $string11 = /\/zerologon\.py/ nocase ascii wide
                        $string12 = /\\monkey\.exe\s/ nocase ascii wide
                        $string13 = /\\monkey32\.exe/ nocase ascii wide
                        $string14 = /\\monkey64\.exe/ nocase ascii wide
                        $string15 = /clear_command_history\.py/ nocase ascii wide
                        $string16 = /communicate_as_backdoor_user\.py/ nocase ascii wide
                        $string17 = /dump_secrets\.py/ nocase ascii wide
                        $string18 = "guardicore/monkey" nocase ascii wide
                        $string19 = /hook\-infection_monkey\.exploit\.py/ nocase ascii wide
                        $string20 = /hook\-infection_monkey\.network\.py/ nocase ascii wide
                        $string21 = /hook\-infection_monkey\.post_breach\.actions\.py/ nocase ascii wide
                        $string22 = /hook\-infection_monkey\.post_breach\.py/ nocase ascii wide
                        $string23 = /hook\-infection_monkey\.ransomware\.py/ nocase ascii wide
                        $string24 = /hook\-infection_monkey\.system_info\.collectors\.py/ nocase ascii wide
                        $string25 = /hook\-pypsrp\.py/ nocase ascii wide
                        $string26 = /HostExploiter\.py/ nocase ascii wide
                        $string27 = /infection_monkey\.py/ nocase ascii wide
                        $string28 = /linux_trap_command\.py/
                        $string29 = /mimikatz_cred_collector\.py/ nocase ascii wide
                        $string30 = /Monkey\sIsland\sv.{0,100}_windows\.exe/ nocase ascii wide
                        $string31 = /monkey.{0,100}tunnel\.py/ nocase ascii wide
                        $string32 = /monkey\\infection_monkey/ nocase ascii wide
                        $string33 = /monkey_island\.exe/ nocase ascii wide
                        $string34 = /monkey32\.exe\s/ nocase ascii wide
                        $string35 = /monkey64\.exe\s/ nocase ascii wide
                        $string36 = "monkey-linux-32"
                        $string37 = "monkey-linux-64"
                        $string38 = /monkey\-windows\-32\.exe/ nocase ascii wide
                        $string39 = /monkey\-windows\-64\.exe/ nocase ascii wide
                        $string40 = /post_breach_handler\.py/ nocase ascii wide
                        $string41 = /pypykatz_handler\.py/ nocase ascii wide
                        $string42 = /ransomware_config\.py/ nocase ascii wide
                        $string43 = /ransomware_payload\.py/ nocase ascii wide
                        $string44 = /remote_shell\.py/ nocase ascii wide
                        $string45 = /run_server\.bat/ nocase ascii wide
                        $string46 = /setuid_setgid\.py/ nocase ascii wide
                        $string47 = /shell_startup_files_modification\.py/ nocase ascii wide
                        $string48 = /victim_host_generator\.py/ nocase ascii wide
                        $string49 = /windows_credentials\.py/ nocase ascii wide
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
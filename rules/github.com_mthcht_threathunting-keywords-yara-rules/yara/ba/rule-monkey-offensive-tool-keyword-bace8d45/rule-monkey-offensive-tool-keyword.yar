rule rule_monkey_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'monkey' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "monkey"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_monkey_offensive_tool_keyword = /\.\/monkey\.sh/
                        $string2_monkey_offensive_tool_keyword = "/infection_monkey/" nocase ascii wide
                        $string3_monkey_offensive_tool_keyword = /\/log4shell\.py/ nocase ascii wide
                        $string4_monkey_offensive_tool_keyword = /\/monkey\.py/ nocase ascii wide
                        $string5_monkey_offensive_tool_keyword = /\/monkey_island\.py/ nocase ascii wide
                        $string6_monkey_offensive_tool_keyword = /\/shellshock\.py/ nocase ascii wide
                        $string7_monkey_offensive_tool_keyword = /\/smbexec\.py/ nocase ascii wide
                        $string8_monkey_offensive_tool_keyword = /\/timestomping\.ps1/ nocase ascii wide
                        $string9_monkey_offensive_tool_keyword = /\/trap_command\.py/ nocase ascii wide
                        $string10_monkey_offensive_tool_keyword = /\/web_rce\.py/ nocase ascii wide
                        $string11_monkey_offensive_tool_keyword = /\/zerologon\.py/ nocase ascii wide
                        $string12_monkey_offensive_tool_keyword = /\\monkey\.exe\s/ nocase ascii wide
                        $string13_monkey_offensive_tool_keyword = /\\monkey32\.exe/ nocase ascii wide
                        $string14_monkey_offensive_tool_keyword = /\\monkey64\.exe/ nocase ascii wide
                        $string15_monkey_offensive_tool_keyword = /clear_command_history\.py/ nocase ascii wide
                        $string16_monkey_offensive_tool_keyword = /communicate_as_backdoor_user\.py/ nocase ascii wide
                        $string17_monkey_offensive_tool_keyword = /dump_secrets\.py/ nocase ascii wide
                        $string18_monkey_offensive_tool_keyword = "guardicore/monkey" nocase ascii wide
                        $string19_monkey_offensive_tool_keyword = /hook\-infection_monkey\.exploit\.py/ nocase ascii wide
                        $string20_monkey_offensive_tool_keyword = /hook\-infection_monkey\.network\.py/ nocase ascii wide
                        $string21_monkey_offensive_tool_keyword = /hook\-infection_monkey\.post_breach\.actions\.py/ nocase ascii wide
                        $string22_monkey_offensive_tool_keyword = /hook\-infection_monkey\.post_breach\.py/ nocase ascii wide
                        $string23_monkey_offensive_tool_keyword = /hook\-infection_monkey\.ransomware\.py/ nocase ascii wide
                        $string24_monkey_offensive_tool_keyword = /hook\-infection_monkey\.system_info\.collectors\.py/ nocase ascii wide
                        $string25_monkey_offensive_tool_keyword = /hook\-pypsrp\.py/ nocase ascii wide
                        $string26_monkey_offensive_tool_keyword = /HostExploiter\.py/ nocase ascii wide
                        $string27_monkey_offensive_tool_keyword = /infection_monkey\.py/ nocase ascii wide
                        $string28_monkey_offensive_tool_keyword = /linux_trap_command\.py/
                        $string29_monkey_offensive_tool_keyword = /mimikatz_cred_collector\.py/ nocase ascii wide
                        $string30_monkey_offensive_tool_keyword = /Monkey\sIsland\sv.{0,100}_windows\.exe/ nocase ascii wide
                        $string31_monkey_offensive_tool_keyword = /monkey.{0,100}tunnel\.py/ nocase ascii wide
                        $string32_monkey_offensive_tool_keyword = /monkey\\infection_monkey/ nocase ascii wide
                        $string33_monkey_offensive_tool_keyword = /monkey_island\.exe/ nocase ascii wide
                        $string34_monkey_offensive_tool_keyword = /monkey32\.exe\s/ nocase ascii wide
                        $string35_monkey_offensive_tool_keyword = /monkey64\.exe\s/ nocase ascii wide
                        $string36_monkey_offensive_tool_keyword = "monkey-linux-32"
                        $string37_monkey_offensive_tool_keyword = "monkey-linux-64"
                        $string38_monkey_offensive_tool_keyword = /monkey\-windows\-32\.exe/ nocase ascii wide
                        $string39_monkey_offensive_tool_keyword = /monkey\-windows\-64\.exe/ nocase ascii wide
                        $string40_monkey_offensive_tool_keyword = /post_breach_handler\.py/ nocase ascii wide
                        $string41_monkey_offensive_tool_keyword = /pypykatz_handler\.py/ nocase ascii wide
                        $string42_monkey_offensive_tool_keyword = /ransomware_config\.py/ nocase ascii wide
                        $string43_monkey_offensive_tool_keyword = /ransomware_payload\.py/ nocase ascii wide
                        $string44_monkey_offensive_tool_keyword = /remote_shell\.py/ nocase ascii wide
                        $string45_monkey_offensive_tool_keyword = /run_server\.bat/ nocase ascii wide
                        $string46_monkey_offensive_tool_keyword = /setuid_setgid\.py/ nocase ascii wide
                        $string47_monkey_offensive_tool_keyword = /shell_startup_files_modification\.py/ nocase ascii wide
                        $string48_monkey_offensive_tool_keyword = /victim_host_generator\.py/ nocase ascii wide
                        $string49_monkey_offensive_tool_keyword = /windows_credentials\.py/ nocase ascii wide
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
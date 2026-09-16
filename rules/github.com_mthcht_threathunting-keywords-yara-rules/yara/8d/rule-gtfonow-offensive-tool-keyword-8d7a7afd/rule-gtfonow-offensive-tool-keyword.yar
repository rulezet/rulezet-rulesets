rule rule_GTFONow_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GTFONow' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GTFONow"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GTFONow_offensive_tool_keyword = /\sgtfobin_update\.py/ nocase ascii wide
                        $string2_GTFONow_offensive_tool_keyword = /\sgtfonow\.py/ nocase ascii wide
                        $string3_GTFONow_offensive_tool_keyword = /\slibpwn\.c/ nocase ascii wide
                        $string4_GTFONow_offensive_tool_keyword = /\slibpwn\.so/ nocase ascii wide
                        $string5_GTFONow_offensive_tool_keyword = /\stest_privesc\.py/ nocase ascii wide
                        $string6_GTFONow_offensive_tool_keyword = /\/gtfobin_update\.py/ nocase ascii wide
                        $string7_GTFONow_offensive_tool_keyword = /\/gtfonow\.py/ nocase ascii wide
                        $string8_GTFONow_offensive_tool_keyword = "/home/lowpriv/"
                        $string9_GTFONow_offensive_tool_keyword = /\/test_privesc\.py/ nocase ascii wide
                        $string10_GTFONow_offensive_tool_keyword = /\/tmp\/gtfokey\.pub/
                        $string11_GTFONow_offensive_tool_keyword = /\/tmp\/libpwn\.c/
                        $string12_GTFONow_offensive_tool_keyword = /\/tmp\/libpwn\.so/
                        $string13_GTFONow_offensive_tool_keyword = /\[\!\]\sFound\sexploitable\ssgid\sbinary/ nocase ascii wide
                        $string14_GTFONow_offensive_tool_keyword = /\[\!\]\sFound\sexploitable\sSudo\sNOPASSWD\sbinary/
                        $string15_GTFONow_offensive_tool_keyword = /\[\!\]\sFound\sexploitable\ssuid\sbinary/ nocase ascii wide
                        $string16_GTFONow_offensive_tool_keyword = /\[\+\]\sSpawning\sroot\sshell/ nocase ascii wide
                        $string17_GTFONow_offensive_tool_keyword = /\\gtfonow\.py/ nocase ascii wide
                        $string18_GTFONow_offensive_tool_keyword = "1b220d5538e63244c3b81a0c7a83ebb9ac7b0cdaed9f3e84057a812d7192b9b2" nocase ascii wide
                        $string19_GTFONow_offensive_tool_keyword = "7c8dcea2da2cd78b706f7e08ff49f7733008ce357fba21777d17334abf0458a6" nocase ascii wide
                        $string20_GTFONow_offensive_tool_keyword = /check_sudo_nopasswd_binaries\(/
                        $string21_GTFONow_offensive_tool_keyword = /cron_priv_esc\(payload/ nocase ascii wide
                        $string22_GTFONow_offensive_tool_keyword = "db62ef03d6be4778d3ec0fd2f6cb2cf030f02a70efa1f30850b27e0cefd50e9e" nocase ascii wide
                        $string23_GTFONow_offensive_tool_keyword = /display_privilege_escalation_options\(/ nocase ascii wide
                        $string24_GTFONow_offensive_tool_keyword = /execute_payload\(priv_esc/ nocase ascii wide
                        $string25_GTFONow_offensive_tool_keyword = "Frissi0n/GTFONow" nocase ascii wide
                        $string26_GTFONow_offensive_tool_keyword = /from\sgtfonow\./ nocase ascii wide
                        $string27_GTFONow_offensive_tool_keyword = "getcap not found in PATH, cannot escalate using capabilities" nocase ascii wide
                        $string28_GTFONow_offensive_tool_keyword = /gtfonow\.py\s\-a/ nocase ascii wide
                        $string29_GTFONow_offensive_tool_keyword = /is_binary_in_gtfobins\(/ nocase ascii wide
                        $string30_GTFONow_offensive_tool_keyword = /perform_privilege_escalation_checks\(/ nocase ascii wide
                        $string31_GTFONow_offensive_tool_keyword = /ssh_key_privesc\(payload/ nocase ascii wide
                        $string32_GTFONow_offensive_tool_keyword = /ssh_write_privesc\(payload/ nocase ascii wide
                        $string33_GTFONow_offensive_tool_keyword = "ssh-keygen not found in PATH, cannot escalate using SSH key" nocase ascii wide
                        $string34_GTFONow_offensive_tool_keyword = "Thanks for using GTFONow!" nocase ascii wide
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
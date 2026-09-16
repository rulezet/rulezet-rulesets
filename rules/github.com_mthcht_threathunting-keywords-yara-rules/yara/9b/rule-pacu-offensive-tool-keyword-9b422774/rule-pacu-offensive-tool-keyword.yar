rule rule_pacu_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pacu' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pacu"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_pacu_offensive_tool_keyword = " --pacu-help" nocase ascii wide
                        $string2_pacu_offensive_tool_keyword = /\/\.local\/share\/pacu\//
                        $string3_pacu_offensive_tool_keyword = /\/acm_enum_cas_.{0,100}\.json/
                        $string4_pacu_offensive_tool_keyword = /\/acm_enum_certs_.{0,100}\.json/
                        $string5_pacu_offensive_tool_keyword = /\/acm_enum_certs_chain_.{0,100}\.json/
                        $string6_pacu_offensive_tool_keyword = /\/acm_enum_certs_expired_.{0,100}\.json/
                        $string7_pacu_offensive_tool_keyword = /\/acm_enum_certs_info_.{0,100}\.json/
                        $string8_pacu_offensive_tool_keyword = "/aws__enum_account"
                        $string9_pacu_offensive_tool_keyword = /\/aws__enum_account\/main\.py/
                        $string10_pacu_offensive_tool_keyword = /\/backdoor_all_users\.py/ nocase ascii wide
                        $string11_pacu_offensive_tool_keyword = "/cfn__resource_injection_lambda"
                        $string12_pacu_offensive_tool_keyword = /\/cmd_log\.txt/
                        $string13_pacu_offensive_tool_keyword = "/ec2__backdoor_ec2_sec_groups" nocase ascii wide
                        $string14_pacu_offensive_tool_keyword = /\/ec2__check_termination_protection.{0,100}\.py/
                        $string15_pacu_offensive_tool_keyword = /\/ec2__startup_shell_script\/main\.py/
                        $string16_pacu_offensive_tool_keyword = /\/ec2_public_ips_.{0,100}_.{0,100}\.txt/
                        $string17_pacu_offensive_tool_keyword = /\/enum__secrets\/.{0,100}\.py/ nocase ascii wide
                        $string18_pacu_offensive_tool_keyword = "/iam__backdoor_users_password" nocase ascii wide
                        $string19_pacu_offensive_tool_keyword = "/iam__bruteforce_permissions/" nocase ascii wide
                        $string20_pacu_offensive_tool_keyword = "/iam__privesc_scan"
                        $string21_pacu_offensive_tool_keyword = "/lambda__backdoor_new_roles" nocase ascii wide
                        $string22_pacu_offensive_tool_keyword = "/lambda__backdoor_new_sec_groups" nocase ascii wide
                        $string23_pacu_offensive_tool_keyword = "/lambda__backdoor_new_users" nocase ascii wide
                        $string24_pacu_offensive_tool_keyword = /\/pacu\.git/ nocase ascii wide
                        $string25_pacu_offensive_tool_keyword = "/vpc__enum_lateral_movement" nocase ascii wide
                        $string26_pacu_offensive_tool_keyword = /\/waf__enum\/main\.py/
                        $string27_pacu_offensive_tool_keyword = /\=MSEXCEL.{0,100}regsvr32\s\/s\s\/n\s\/u\s\/i\:http.{0,100}\/SCTLauncher\.sct\sscrobj\.dll/ nocase ascii wide
                        $string28_pacu_offensive_tool_keyword = "cloudtrail__csv_injection" nocase ascii wide
                        $string29_pacu_offensive_tool_keyword = /docker\srun\s.{0,100}\/pacu\:latest/ nocase ascii wide
                        $string30_pacu_offensive_tool_keyword = /ecs_task_def_data\/all_task_def\.txt/ nocase ascii wide
                        $string31_pacu_offensive_tool_keyword = /iam__enum_assume_role\/default\-word\-list\.txt/ nocase ascii wide
                        $string32_pacu_offensive_tool_keyword = "lambda__backdoor_new_sec_groups" nocase ascii wide
                        $string33_pacu_offensive_tool_keyword = "pacu --exec " nocase ascii wide
                        $string34_pacu_offensive_tool_keyword = "pacu --list-modules" nocase ascii wide
                        $string35_pacu_offensive_tool_keyword = "pacu --module-args=" nocase ascii wide
                        $string36_pacu_offensive_tool_keyword = "pacu --module-info" nocase ascii wide
                        $string37_pacu_offensive_tool_keyword = "pacu --module-name " nocase ascii wide
                        $string38_pacu_offensive_tool_keyword = "pacu --session " nocase ascii wide
                        $string39_pacu_offensive_tool_keyword = "pacu --set-regions " nocase ascii wide
                        $string40_pacu_offensive_tool_keyword = "pacu --whoami" nocase ascii wide
                        $string41_pacu_offensive_tool_keyword = "pacu/core pacu" nocase ascii wide
                        $string42_pacu_offensive_tool_keyword = /pacu\/last_update\.txt/ nocase ascii wide
                        $string43_pacu_offensive_tool_keyword = /pacu\-master\.zip/ nocase ascii wide
                        $string44_pacu_offensive_tool_keyword = "pip3 install -U pacu" nocase ascii wide
                        $string45_pacu_offensive_tool_keyword = /python3\spacu\.py/ nocase ascii wide
                        $string46_pacu_offensive_tool_keyword = "RhinoSecurityLabs/pacu" nocase ascii wide
                        $string47_pacu_offensive_tool_keyword = /secrets\/secrets_manager\/secrets\.txt/ nocase ascii wide
                        $string48_pacu_offensive_tool_keyword = /test_pacu_update\.py/ nocase ascii wide
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
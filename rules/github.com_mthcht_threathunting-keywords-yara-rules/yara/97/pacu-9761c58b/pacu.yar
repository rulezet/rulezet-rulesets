rule pacu
{
    meta:
        description = "Detection patterns for the tool 'pacu' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pacu"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --pacu-help" nocase ascii wide
                        $string2 = /\/\.local\/share\/pacu\//
                        $string3 = /\/acm_enum_cas_.{0,1000}\.json/
                        $string4 = /\/acm_enum_certs_.{0,1000}\.json/
                        $string5 = /\/acm_enum_certs_chain_.{0,1000}\.json/
                        $string6 = /\/acm_enum_certs_expired_.{0,1000}\.json/
                        $string7 = /\/acm_enum_certs_info_.{0,1000}\.json/
                        $string8 = "/aws__enum_account"
                        $string9 = /\/aws__enum_account\/main\.py/
                        $string10 = /\/backdoor_all_users\.py/ nocase ascii wide
                        $string11 = "/cfn__resource_injection_lambda"
                        $string12 = /\/cmd_log\.txt/
                        $string13 = "/ec2__backdoor_ec2_sec_groups" nocase ascii wide
                        $string14 = /\/ec2__check_termination_protection.{0,1000}\.py/
                        $string15 = /\/ec2__startup_shell_script\/main\.py/
                        $string16 = /\/ec2_public_ips_.{0,1000}_.{0,1000}\.txt/
                        $string17 = /\/enum__secrets\/.{0,1000}\.py/ nocase ascii wide
                        $string18 = "/iam__backdoor_users_password" nocase ascii wide
                        $string19 = "/iam__bruteforce_permissions/" nocase ascii wide
                        $string20 = "/iam__privesc_scan"
                        $string21 = "/lambda__backdoor_new_roles" nocase ascii wide
                        $string22 = "/lambda__backdoor_new_sec_groups" nocase ascii wide
                        $string23 = "/lambda__backdoor_new_users" nocase ascii wide
                        $string24 = /\/pacu\.git/ nocase ascii wide
                        $string25 = "/vpc__enum_lateral_movement" nocase ascii wide
                        $string26 = /\/waf__enum\/main\.py/
                        $string27 = /\=MSEXCEL.{0,1000}regsvr32\s\/s\s\/n\s\/u\s\/i\:http.{0,1000}\/SCTLauncher\.sct\sscrobj\.dll/ nocase ascii wide
                        $string28 = "cloudtrail__csv_injection" nocase ascii wide
                        $string29 = /docker\srun\s.{0,1000}\/pacu\:latest/ nocase ascii wide
                        $string30 = /ecs_task_def_data\/all_task_def\.txt/ nocase ascii wide
                        $string31 = /iam__enum_assume_role\/default\-word\-list\.txt/ nocase ascii wide
                        $string32 = "lambda__backdoor_new_sec_groups" nocase ascii wide
                        $string33 = "pacu --exec " nocase ascii wide
                        $string34 = "pacu --list-modules" nocase ascii wide
                        $string35 = "pacu --module-args=" nocase ascii wide
                        $string36 = "pacu --module-info" nocase ascii wide
                        $string37 = "pacu --module-name " nocase ascii wide
                        $string38 = "pacu --session " nocase ascii wide
                        $string39 = "pacu --set-regions " nocase ascii wide
                        $string40 = "pacu --whoami" nocase ascii wide
                        $string41 = "pacu/core pacu" nocase ascii wide
                        $string42 = /pacu\/last_update\.txt/ nocase ascii wide
                        $string43 = /pacu\-master\.zip/ nocase ascii wide
                        $string44 = "pip3 install -U pacu" nocase ascii wide
                        $string45 = /python3\spacu\.py/ nocase ascii wide
                        $string46 = "RhinoSecurityLabs/pacu" nocase ascii wide
                        $string47 = /secrets\/secrets_manager\/secrets\.txt/ nocase ascii wide
                        $string48 = /test_pacu_update\.py/ nocase ascii wide

    condition:
        any of them
}
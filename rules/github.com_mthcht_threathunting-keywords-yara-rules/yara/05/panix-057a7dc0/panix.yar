rule panix
{
    meta:
        description = "Detection patterns for the tool 'panix' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "panix"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --backdoor-user "
                        $string2 = " --malicious-package "
                        $string3 = /\spanix\.sh\s\-\-/
                        $string4 = /\spanix\.sh\s\-\-generator/
                        $string5 = /\spanix\.sh\s\-\-generator/
                        $string6 = /\spanix\.sh\s\-\-systemd/
                        $string7 = " --sudoers-backdoor"
                        $string8 = /\#\!\/bin\/bash\\n\/bin\/bash\s\-c\s\'sh\s\-i\s\>\&\s\/dev\/tcp\/.{0,100}\/.{0,100}\s0\>\&1/
                        $string9 = /\.sh\s\-\-at\s\-\-custom\s\-\-command\s.{0,100}\s\-\-time\s/
                        $string10 = /\.sh\s\-\-authorized\-keys\s\-\-custom\s\-\-key\s.{0,100}\.ssh\/authorized_keys/
                        $string11 = /\.sh\s\-\-backdoor\-user\s\-\-username\s/
                        $string12 = /\.sh\s\-\-cron\s\-\-custom\s\-\-command\s.{0,100}\s\-\-crond\s\-\-name\s/
                        $string13 = /\.sh\s\-\-cron\s\-\-custom\s\-\-command\s.{0,100}\s\-\-crontab/
                        $string14 = /\.sh\s\-\-cron\s\-\-custom\s\-\-command\s.{0,100}\s\-\-daily\s\-\-name\s/
                        $string15 = /\.sh\s\-\-passwd\-user\s\-\-custom\s\-\-passwd\-string\s/
                        $string16 = /\.sh\s\-\-shell\-profile\s\-\-custom\s\-\-command\s.{0,100}\s\-\-path\s.{0,100}\/\.bash_profile/
                        $string17 = /\.sh\s\-\-systemd\s\-\-custom\s\-\-command\s/
                        $string18 = /\.sh\s\-\-systemd\s\-\-default\s\-\-ip\s.{0,100}\s\-\-port\s/
                        $string19 = /\.sh\s\-\-udev\s\-\-custom\s\-\-command\s/
                        $string20 = /\.sh\s\-\-xdg\s\-\-custom\s\-\-command\s.{0,100}\s\-\-path\s.{0,100}\/etc\/xdg\/autostart\//
                        $string21 = /\/etc\/xdg\/autostart\/evilxdg\.desktop/
                        $string22 = /\/lib\/systemd\/system\/evil\.service/
                        $string23 = /\/PANIX\.git/
                        $string24 = /\/panix\.sh\s\-\-/
                        $string25 = /\/releases\/download\/panix\-v.{0,100}\/panix\.sh/
                        $string26 = "/usr/bin/at -M -f /tmp/payload"
                        $string27 = "/usr/bin/at -M -f /usr/bin/atest"
                        $string28 = /\/usr\/bin\/bash\s\-c\s\'bash\s\-i\s\>\&\s\/dev\/tcp\/\$ip\/\$port\s0\>\&1/
                        $string29 = /\/usr\/local\/bin\/escape\.sh/
                        $string30 = ":0:0:root:/root:/bin/bash\" >> /etc/passwd"
                        $string31 = /\[\-\]\sFailed\sto\screate\ssudoers\sbackdoor\sfor\suser\s/
                        $string32 = /\[\+\]\s\$bin\sbackdoored\ssuccessful/
                        $string33 = /\[\+\]\s\$binary\sbackdoored\ssuccessful/
                        $string34 = /\[\+\]\s\/etc\/passwd\spersistence\sestablished\!/
                        $string35 = /\[\+\]\sAPT\spersistence\sestablis/
                        $string36 = /\[\+\]\sAt\sjob\spersistence\sestablish/
                        $string37 = /\[\+\]\sAuthorized_keys\spersistence\sestablish/
                        $string38 = /\[\+\]\sBackdoor\suser\spersistence\sestablish/
                        $string39 = /\[\+\]\sBackdoor\suser\spersistence\sestablished\!/
                        $string40 = /\[\+\]\sBind\sshell\spersistence\sestablish/
                        $string41 = /\[\+\]\sCapabilities\sbackdoor\spersistence\sestablish/
                        $string42 = /\[\+\]\sCreated\smalicious\spre\-commit\shook\sin\s/
                        $string43 = /\[\+\]\sCron\spersistence\sestablished/
                        $string44 = /\[\+\]\sDocker\scontainer\spersistence\sestablish/
                        $string45 = /\[\+\]\sGit\spersistence\sestablish/
                        $string46 = /\[\+\]\sinit\.d\sbackdoor\sestablish/
                        $string47 = /\[\+\]\sMOTD\sbackdoor\spersistence\sestablish/
                        $string48 = /\[\+\]\sRemoved\smalicious\sentry\sfrom\spre\-commit\shook\sin\s/
                        $string49 = /\[\+\]\sSSH\skey\spersistence\sestablished\!/
                        $string50 = /\[\+\]\sSystemd\sGenerator\spersistence\sestablished\!/
                        $string51 = /\[\+\]\sUser\s.{0,100}\sadded\sto\s\/etc\/passwd\swith\sroot\sprivileges\./
                        $string52 = /\[\+\]\sUser\s.{0,100}\shas\sbeen\smodified\sto\shave\sUID\s0\s\(root\sprivileges\)\./
                        $string53 = /\[\+\]\sUser\spersistence\sthrough\sthe\snew\s.{0,100}\suser\sestablished\!/
                        $string54 = /\[\+\]\sXDG\spersistence\sestablished\!/
                        $string55 = /\]\sCleaning\sAt\spersistence\smethods/
                        $string56 = /\]\sCleaning\sBackdoor\sbinaries\spersistence\smethods/
                        $string57 = /\]\sCleaning\sBind\sshell\spersistence\smethods/
                        $string58 = /\]\sCleaning\sCron\spersistence\smethods/
                        $string59 = /\]\sCleaning\sDocker\spersistence\smethods/
                        $string60 = /\]\sCleaning\sGit\spersistence\smethods/
                        $string61 = /\]\sCleaning\sinitd\spersistence\smethods/
                        $string62 = /\]\sCleaning\sMalicious\spackage\spersistence\smethods/
                        $string63 = /\]\sCleaning\sMOTD\spersistence\smethods/
                        $string64 = /\]\sCleaning\sPackage\sManagers\spersistence\smethods/
                        $string65 = /\]\sCleaning\src\.local\spersistence\smethods/
                        $string66 = /\]\sCleaning\ssetcap\spersistence\smethods/
                        $string67 = /\]\sCleaning\sSetuid\spersistence\smethods/
                        $string68 = /\]\sCleaning\sShell\sprofile\spersistence\smethods/
                        $string69 = /\]\sCleaning\sSSH\spersistence\smethods/
                        $string70 = /\]\sCleaning\sSudoers\spersistence\smethods/
                        $string71 = /\]\sCleaning\sSystemd\sGenerator\spersistence\smethods/
                        $string72 = /\]\sCleaning\sSystemd\spersistence\smethods/
                        $string73 = /\]\sCleaning\sudev\spersistence\smethods/
                        $string74 = /\]\sCleaning\sXDG\spersistence\smethods/
                        $string75 = "7cd720218d9cf22a1143274f4904f30bcef18bfc00ebb54de45bedfeb12d1535"
                        $string76 = "8c842d7dfb5c081a394e645377db303da5228ee78ff9467c4f00534ba8e0c389"
                        $string77 = "974cf826367e6b3bd96006f325a549d892da924bf76afc7df546e31ede536696"
                        $string78 = "add_malicious_pager"
                        $string79 = "add_malicious_pre_commit"
                        $string80 = "Aegrah/PANIX"
                        $string81 = "c3663dba552ca6aa8d2c0f36fccc553d728b37464944080398f72f487430710f"
                        $string82 = /cat\s.{0,100}\.pub\s\>\>\s.{0,100}\/authorized_keys/
                        $string83 = "cat <<-EOF > /usr/lib/systemd/system-generators/generator"
                        $string84 = /chmod\s\+x\s\/usr\/lib\/systemd\/system\-generators\/makecon/
                        $string85 = "echo \"@RFGroenewoud\""
                        $string86 = "f0VMRgEBAQAAAAAAAAAAAAIAAwABAAAAVIAECDQAAAAAAAAAAAAAADQAIAABAAAAAAAAAAEAAAAAAAAAAIAECACABAiiAAAA8AAAAAcAAAAAEAAAMdv341NDU2oCieGwZs2AW15SaAIAIylqEFFQieFqZljNgIlBBLMEsGbNgEOwZs2Ak1lqP1jNgEl5"
                        $string87 = "f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAeABAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAOAABAAAAAAAAAAEAAAAHAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAzgAAAAAAAAAkAQAAAAAAAAAQAAAAAAAAailYmWoCX2oBXg8FSJdSxwQkAgAjKUiJ5moQWmoxWA8FajJYDwVIMfZqK1gPBUiXagNeSP"
                        $string88 = /ln\s\-s\s\/run\/systemd\/system\/generator\.service\s\/run\/systemd\/system\/multi\-user\.target\.wants\/generator\.service/
                        $string89 = /nohup\sbash\s\-c\s\\"while\s\:\;\sdo\sbash\s\-i\s\>\&\s\/dev\/tcp\/.{0,100}\/.{0,100}\s0\>\&1\;\ssleep\s10\;\sdone/
                        $string90 = /panix\.sh\s\-\-ssh\-key\s/
                        $string91 = "setup_backdoor_user"
                        $string92 = "setup_cap_backdoor"
                        $string93 = "setup_generator_persistence"
                        $string94 = "setup_git_persistence"
                        $string95 = "setup_initd_backdoor"
                        $string96 = "setup_malicious_docker_container"
                        $string97 = "setup_malicious_package"
                        $string98 = "setup_motd_backdoor"
                        $string99 = "setup_rc_local_backdoor"
                        $string100 = "setup_sudoers_backdoor"
                        $string101 = "setup_suid_backdoor"
                        $string102 = "setup_system_binary_backdoor"
                        $string103 = /sh\s\-i\s\>\&\s\/dev\/tcp\/.{0,100}\/1337\s0\>\&1/
                        $string104 = "sudo nsenter -t 1 -m -u -i -n -p -- su -"
                        $string105 = "usage_backdoor_user"
                        $string106 = "usage_initd_backdoor"
                        $string107 = "usage_malicious_docker_container"
                        $string108 = "usage_malicious_package"
                        $string109 = "usage_motd_backdoor"
                        $string110 = "usage_package_manager_persistence"
                        $string111 = "usage_rc_local_backdoor"
                        $string112 = "usage_sudoers_backdoor"
                        $string113 = "usage_suid_backdoor"
                        $string114 = "usage_system_binary_backdoor"
                        $string115 = "usermod -u 0 -o "
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
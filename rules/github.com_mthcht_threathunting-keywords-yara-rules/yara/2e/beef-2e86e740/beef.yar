rule beef
{
    meta:
        description = "Detection patterns for the tool 'beef' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "beef"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\/update\-beef/
                        $string2 = /\/beef\.git/ nocase ascii wide
                        $string3 = /\/beef\/extensions\/.{0,100}\.rb/ nocase ascii wide
                        $string4 = "/beef_bind_shell/" nocase ascii wide
                        $string5 = /\/beef_common\.js/ nocase ascii wide
                        $string6 = "/beefbind/" nocase ascii wide
                        $string7 = "/beefproject/" nocase ascii wide
                        $string8 = /\/bind_powershell\.rb/ nocase ascii wide
                        $string9 = /\/client\/beef\.js/ nocase ascii wide
                        $string10 = /\/detect_antivirus\/.{0,100}\.js/ nocase ascii wide
                        $string11 = /\/detect_antivirus\/.{0,100}\.rb/ nocase ascii wide
                        $string12 = /\/hijack_opener\/.{0,100}\.js/ nocase ascii wide
                        $string13 = /\/hijack_opener\/.{0,100}\.rb/ nocase ascii wide
                        $string14 = /\/man_in_the_browser\/.{0,100}\.js/ nocase ascii wide
                        $string15 = /\/man_in_the_browser\/.{0,100}\.rb/ nocase ascii wide
                        $string16 = "/shellcode_sources/" nocase ascii wide
                        $string17 = "/simple_hijacker/" nocase ascii wide
                        $string18 = "/thirdparty/msf/"
                        $string19 = /_dns_hijack\/.{0,100}\.js/ nocase ascii wide
                        $string20 = /_dns_hijack\/.{0,100}\.rb/ nocase ascii wide
                        $string21 = "apache_felix_remote_shell" nocase ascii wide
                        $string22 = /Applet_ReverseTCP\.jar/ nocase ascii wide
                        $string23 = "beef:beef" nocase ascii wide
                        $string24 = /beef_bind_tcp\-stage\.asm/ nocase ascii wide
                        $string25 = /beef_bind_tcp\-stager\.asm/ nocase ascii wide
                        $string26 = /beef_bind\-stage.{0,100}\.rb/ nocase ascii wide
                        $string27 = /beef_bind\-stage\.asm/ nocase ascii wide
                        $string28 = /beef_bind\-stager\.asm/ nocase ascii wide
                        $string29 = /beef_test\.rb/ nocase ascii wide
                        $string30 = "beefproject" nocase ascii wide
                        $string31 = "beef-xss" nocase ascii wide
                        $string32 = "browser_autopwn" nocase ascii wide
                        $string33 = /chromecertbeggar\.js/ nocase ascii wide
                        $string34 = /chromecertbeggar2\.js/ nocase ascii wide
                        $string35 = /clickjack_attack\.html/ nocase ascii wide
                        $string36 = /clickjack_victim\.html/ nocase ascii wide
                        $string37 = "coldfusion_dir_traversal_exploit" nocase ascii wide
                        $string38 = /ContentHijacking\.swf/ nocase ascii wide
                        $string39 = "csrf_to_beef" nocase ascii wide
                        $string40 = "dlink_sharecenter_cmd_exec" nocase ascii wide
                        $string41 = "edge_wscript_wsh_injection" nocase ascii wide
                        $string42 = /exploit.{0,100}wordpress_add_admin/ nocase ascii wide
                        $string43 = /exploits.{0,100}_csrf\/.{0,100}\.js/ nocase ascii wide
                        $string44 = /exploits.{0,100}_csrf\/.{0,100}\.rb/ nocase ascii wide
                        $string45 = /extract_cmd_exec.{0,100}\.js/ nocase ascii wide
                        $string46 = /extract_cmd_exec.{0,100}\.rb/ nocase ascii wide
                        $string47 = "fake_evernote_clipper" nocase ascii wide
                        $string48 = "fake_flash_update" nocase ascii wide
                        $string49 = "fake_lastpass/" nocase ascii wide
                        $string50 = "fake_notification_ff/" nocase ascii wide
                        $string51 = "ff_osx_extension-dropper" nocase ascii wide
                        $string52 = "firefox_extension_bindshell" nocase ascii wide
                        $string53 = "firefox_extension_reverse_shell" nocase ascii wide
                        $string54 = "freenas_reverse_root_shell_csrf" nocase ascii wide
                        $string55 = "glassfish_war_upload_xsrf" nocase ascii wide
                        $string56 = /hookedbrowsers\.rb/ nocase ascii wide
                        $string57 = /http.{0,100}\/demos\/butcher\/index\.html/ nocase ascii wide
                        $string58 = /http.{0,100}\:3000\/hook\.js/ nocase ascii wide
                        $string59 = /http\:\/\/127\.0\.0\.1\:3000\/ui\/panel/ nocase ascii wide
                        $string60 = "http://localhost:3000/ui/panel" nocase ascii wide
                        $string61 = "ie_win_fakenotification-clippy" nocase ascii wide
                        $string62 = /ie_win_htapowershell\./ nocase ascii wide
                        $string63 = "ie_win_missingflash-prettytheft" nocase ascii wide
                        $string64 = "jboss_jmx_upload_exploit" nocase ascii wide
                        $string65 = /lan_fingerprint_common\./ nocase ascii wide
                        $string66 = /lan_ping_sweep\.json/ nocase ascii wide
                        $string67 = /lan_sw_port_scan\.json/ nocase ascii wide
                        $string68 = /man_in_the_browser\.json/ nocase ascii wide
                        $string69 = /modules\/exploits\/.{0,100}\.js/ nocase ascii wide
                        $string70 = /modules\/exploits\/.{0,100}\.rb/ nocase ascii wide
                        $string71 = /pfsense.{0,100}reverse_root_shell_csrf\// nocase ascii wide
                        $string72 = /portscanner\.js/ nocase ascii wide
                        $string73 = "replace_video_fake_plugin" nocase ascii wide
                        $string74 = "ruby_nntpd_cmd_exec" nocase ascii wide
                        $string75 = /shell_shocked.{0,100}\.js/ nocase ascii wide
                        $string76 = /shell_shocked.{0,100}\.rb/ nocase ascii wide
                        $string77 = "social_engineering/web_cloner" nocase ascii wide
                        $string78 = "spring_framework_malicious_jar" nocase ascii wide
                        $string79 = "test_beef_debugs_spec" nocase ascii wide
                        $string80 = "vtiger_crm_upload_exploit" nocase ascii wide
                        $string81 = "web_cloner/interceptor" nocase ascii wide
                        $string82 = "wifi_pineapple_csrf" nocase ascii wide
                        $string83 = /win_fake_malware\./ nocase ascii wide
                        $string84 = /xssrays\.js/ nocase ascii wide
                        $string85 = /xssrays\.rb/ nocase ascii wide
                        $string86 = /xssrays_spec\.rb/ nocase ascii wide
                        $string87 = /xssraysdetail\.rb/ nocase ascii wide
                        $string88 = /xssraysscan\.rb/ nocase ascii wide
                        $string89 = "zenoss_3x_command_execution" nocase ascii wide
                        $string90 = /\.\/beef/
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
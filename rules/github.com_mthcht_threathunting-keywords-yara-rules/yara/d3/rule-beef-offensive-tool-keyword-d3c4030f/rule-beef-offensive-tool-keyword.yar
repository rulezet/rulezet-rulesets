rule rule_beef_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'beef' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "beef"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_beef_offensive_tool_keyword = /\.\/update\-beef/
                        $string2_beef_offensive_tool_keyword = /\/beef\.git/ nocase ascii wide
                        $string3_beef_offensive_tool_keyword = /\/beef\/extensions\/.{0,100}\.rb/ nocase ascii wide
                        $string4_beef_offensive_tool_keyword = "/beef_bind_shell/" nocase ascii wide
                        $string5_beef_offensive_tool_keyword = /\/beef_common\.js/ nocase ascii wide
                        $string6_beef_offensive_tool_keyword = "/beefbind/" nocase ascii wide
                        $string7_beef_offensive_tool_keyword = "/beefproject/" nocase ascii wide
                        $string8_beef_offensive_tool_keyword = /\/bind_powershell\.rb/ nocase ascii wide
                        $string9_beef_offensive_tool_keyword = /\/client\/beef\.js/ nocase ascii wide
                        $string10_beef_offensive_tool_keyword = /\/detect_antivirus\/.{0,100}\.js/ nocase ascii wide
                        $string11_beef_offensive_tool_keyword = /\/detect_antivirus\/.{0,100}\.rb/ nocase ascii wide
                        $string12_beef_offensive_tool_keyword = /\/hijack_opener\/.{0,100}\.js/ nocase ascii wide
                        $string13_beef_offensive_tool_keyword = /\/hijack_opener\/.{0,100}\.rb/ nocase ascii wide
                        $string14_beef_offensive_tool_keyword = /\/man_in_the_browser\/.{0,100}\.js/ nocase ascii wide
                        $string15_beef_offensive_tool_keyword = /\/man_in_the_browser\/.{0,100}\.rb/ nocase ascii wide
                        $string16_beef_offensive_tool_keyword = "/shellcode_sources/" nocase ascii wide
                        $string17_beef_offensive_tool_keyword = "/simple_hijacker/" nocase ascii wide
                        $string18_beef_offensive_tool_keyword = "/thirdparty/msf/"
                        $string19_beef_offensive_tool_keyword = /_dns_hijack\/.{0,100}\.js/ nocase ascii wide
                        $string20_beef_offensive_tool_keyword = /_dns_hijack\/.{0,100}\.rb/ nocase ascii wide
                        $string21_beef_offensive_tool_keyword = "apache_felix_remote_shell" nocase ascii wide
                        $string22_beef_offensive_tool_keyword = /Applet_ReverseTCP\.jar/ nocase ascii wide
                        $string23_beef_offensive_tool_keyword = "beef:beef" nocase ascii wide
                        $string24_beef_offensive_tool_keyword = /beef_bind_tcp\-stage\.asm/ nocase ascii wide
                        $string25_beef_offensive_tool_keyword = /beef_bind_tcp\-stager\.asm/ nocase ascii wide
                        $string26_beef_offensive_tool_keyword = /beef_bind\-stage.{0,100}\.rb/ nocase ascii wide
                        $string27_beef_offensive_tool_keyword = /beef_bind\-stage\.asm/ nocase ascii wide
                        $string28_beef_offensive_tool_keyword = /beef_bind\-stager\.asm/ nocase ascii wide
                        $string29_beef_offensive_tool_keyword = /beef_test\.rb/ nocase ascii wide
                        $string30_beef_offensive_tool_keyword = "beefproject" nocase ascii wide
                        $string31_beef_offensive_tool_keyword = "beef-xss" nocase ascii wide
                        $string32_beef_offensive_tool_keyword = "browser_autopwn" nocase ascii wide
                        $string33_beef_offensive_tool_keyword = /chromecertbeggar\.js/ nocase ascii wide
                        $string34_beef_offensive_tool_keyword = /chromecertbeggar2\.js/ nocase ascii wide
                        $string35_beef_offensive_tool_keyword = /clickjack_attack\.html/ nocase ascii wide
                        $string36_beef_offensive_tool_keyword = /clickjack_victim\.html/ nocase ascii wide
                        $string37_beef_offensive_tool_keyword = "coldfusion_dir_traversal_exploit" nocase ascii wide
                        $string38_beef_offensive_tool_keyword = /ContentHijacking\.swf/ nocase ascii wide
                        $string39_beef_offensive_tool_keyword = "csrf_to_beef" nocase ascii wide
                        $string40_beef_offensive_tool_keyword = "dlink_sharecenter_cmd_exec" nocase ascii wide
                        $string41_beef_offensive_tool_keyword = "edge_wscript_wsh_injection" nocase ascii wide
                        $string42_beef_offensive_tool_keyword = /exploit.{0,100}wordpress_add_admin/ nocase ascii wide
                        $string43_beef_offensive_tool_keyword = /exploits.{0,100}_csrf\/.{0,100}\.js/ nocase ascii wide
                        $string44_beef_offensive_tool_keyword = /exploits.{0,100}_csrf\/.{0,100}\.rb/ nocase ascii wide
                        $string45_beef_offensive_tool_keyword = /extract_cmd_exec.{0,100}\.js/ nocase ascii wide
                        $string46_beef_offensive_tool_keyword = /extract_cmd_exec.{0,100}\.rb/ nocase ascii wide
                        $string47_beef_offensive_tool_keyword = "fake_evernote_clipper" nocase ascii wide
                        $string48_beef_offensive_tool_keyword = "fake_flash_update" nocase ascii wide
                        $string49_beef_offensive_tool_keyword = "fake_lastpass/" nocase ascii wide
                        $string50_beef_offensive_tool_keyword = "fake_notification_ff/" nocase ascii wide
                        $string51_beef_offensive_tool_keyword = "ff_osx_extension-dropper" nocase ascii wide
                        $string52_beef_offensive_tool_keyword = "firefox_extension_bindshell" nocase ascii wide
                        $string53_beef_offensive_tool_keyword = "firefox_extension_reverse_shell" nocase ascii wide
                        $string54_beef_offensive_tool_keyword = "freenas_reverse_root_shell_csrf" nocase ascii wide
                        $string55_beef_offensive_tool_keyword = "glassfish_war_upload_xsrf" nocase ascii wide
                        $string56_beef_offensive_tool_keyword = /hookedbrowsers\.rb/ nocase ascii wide
                        $string57_beef_offensive_tool_keyword = /http.{0,100}\/demos\/butcher\/index\.html/ nocase ascii wide
                        $string58_beef_offensive_tool_keyword = /http.{0,100}\:3000\/hook\.js/ nocase ascii wide
                        $string59_beef_offensive_tool_keyword = /http\:\/\/127\.0\.0\.1\:3000\/ui\/panel/ nocase ascii wide
                        $string60_beef_offensive_tool_keyword = "http://localhost:3000/ui/panel" nocase ascii wide
                        $string61_beef_offensive_tool_keyword = "ie_win_fakenotification-clippy" nocase ascii wide
                        $string62_beef_offensive_tool_keyword = /ie_win_htapowershell\./ nocase ascii wide
                        $string63_beef_offensive_tool_keyword = "ie_win_missingflash-prettytheft" nocase ascii wide
                        $string64_beef_offensive_tool_keyword = "jboss_jmx_upload_exploit" nocase ascii wide
                        $string65_beef_offensive_tool_keyword = /lan_fingerprint_common\./ nocase ascii wide
                        $string66_beef_offensive_tool_keyword = /lan_ping_sweep\.json/ nocase ascii wide
                        $string67_beef_offensive_tool_keyword = /lan_sw_port_scan\.json/ nocase ascii wide
                        $string68_beef_offensive_tool_keyword = /man_in_the_browser\.json/ nocase ascii wide
                        $string69_beef_offensive_tool_keyword = /modules\/exploits\/.{0,100}\.js/ nocase ascii wide
                        $string70_beef_offensive_tool_keyword = /modules\/exploits\/.{0,100}\.rb/ nocase ascii wide
                        $string71_beef_offensive_tool_keyword = /pfsense.{0,100}reverse_root_shell_csrf\// nocase ascii wide
                        $string72_beef_offensive_tool_keyword = /portscanner\.js/ nocase ascii wide
                        $string73_beef_offensive_tool_keyword = "replace_video_fake_plugin" nocase ascii wide
                        $string74_beef_offensive_tool_keyword = "ruby_nntpd_cmd_exec" nocase ascii wide
                        $string75_beef_offensive_tool_keyword = /shell_shocked.{0,100}\.js/ nocase ascii wide
                        $string76_beef_offensive_tool_keyword = /shell_shocked.{0,100}\.rb/ nocase ascii wide
                        $string77_beef_offensive_tool_keyword = "social_engineering/web_cloner" nocase ascii wide
                        $string78_beef_offensive_tool_keyword = "spring_framework_malicious_jar" nocase ascii wide
                        $string79_beef_offensive_tool_keyword = "test_beef_debugs_spec" nocase ascii wide
                        $string80_beef_offensive_tool_keyword = "vtiger_crm_upload_exploit" nocase ascii wide
                        $string81_beef_offensive_tool_keyword = "web_cloner/interceptor" nocase ascii wide
                        $string82_beef_offensive_tool_keyword = "wifi_pineapple_csrf" nocase ascii wide
                        $string83_beef_offensive_tool_keyword = /win_fake_malware\./ nocase ascii wide
                        $string84_beef_offensive_tool_keyword = /xssrays\.js/ nocase ascii wide
                        $string85_beef_offensive_tool_keyword = /xssrays\.rb/ nocase ascii wide
                        $string86_beef_offensive_tool_keyword = /xssrays_spec\.rb/ nocase ascii wide
                        $string87_beef_offensive_tool_keyword = /xssraysdetail\.rb/ nocase ascii wide
                        $string88_beef_offensive_tool_keyword = /xssraysscan\.rb/ nocase ascii wide
                        $string89_beef_offensive_tool_keyword = "zenoss_3x_command_execution" nocase ascii wide
                        $string90_beef_offensive_tool_keyword = /\.\/beef/
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
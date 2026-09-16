rule RustDesk
{
    meta:
        description = "Detection patterns for the tool 'RustDesk' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RustDesk"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\sRustDesk\.exe/ nocase ascii wide
                        $string2 = " start rustdesk://" nocase ascii wide
                        $string3 = "/home/user/rustdesk"
                        $string4 = /\/RustDesk\.exe/ nocase ascii wide
                        $string5 = /\/rustdesk\.git/ nocase ascii wide
                        $string6 = "/rustdesk/rustdesk/releases/" nocase ascii wide
                        $string7 = /\\\.rustdesk/ nocase ascii wide
                        $string8 = /\\\\RustDeskIddDriver/ nocase ascii wide
                        $string9 = /\\AppData\\Local\\rustdesk\\/ nocase ascii wide
                        $string10 = /\\config\\RustDesk\.toml/ nocase ascii wide
                        $string11 = /\\config\\RustDesk_local\./ nocase ascii wide
                        $string12 = /\\CurrentVersion\\Uninstall\\RustDesk/ nocase ascii wide
                        $string13 = /\\librustdesk\.dll/ nocase ascii wide
                        $string14 = /\\ProgramData\\RustDesk\\/ nocase ascii wide
                        $string15 = /\\rustdesk\-.{0,100}\-x86_64\.exe/ nocase ascii wide
                        $string16 = /\\RustDesk\.exe/ nocase ascii wide
                        $string17 = /\\RustDesk\.lnk/ nocase ascii wide
                        $string18 = /\\RustDesk\\query/ nocase ascii wide
                        $string19 = /\\RustDeskIddDriver\\/ nocase ascii wide
                        $string20 = /\\test_rustdesk\.log/ nocase ascii wide
                        $string21 = "095e73fc4b115afd77e39a9389ff1eff6bdbff7a" nocase ascii wide
                        $string22 = /HKEY_CLASSES_ROOT\\rustdesk/ nocase ascii wide
                        $string23 = /info\@rustdesk\.com/ nocase ascii wide
                        $string24 = "name=\"RustDesk Service\"" nocase ascii wide
                        $string25 = /rs\-ny\.rustdesk\.com/ nocase ascii wide
                        $string26 = /RuntimeBroker_rustdesk\.exe/ nocase ascii wide
                        $string27 = "RustDesk Service is running" nocase ascii wide
                        $string28 = /rustdesk\-.{0,100}\.apk/ nocase ascii wide
                        $string29 = /rustdesk\-.{0,100}\.deb/ nocase ascii wide
                        $string30 = /rustdesk\-.{0,100}\.dmg/ nocase ascii wide
                        $string31 = /rustdesk\-.{0,100}\.rpm/ nocase ascii wide
                        $string32 = /rustdesk\-.{0,100}\-win7\-install\.exe/ nocase ascii wide
                        $string33 = /RustDesk\.exe\s/ nocase ascii wide
                        $string34 = /RUSTDESK\.EXE\-.{0,100}\.pf/ nocase ascii wide
                        $string35 = /RustDesk_hwcodec\./ nocase ascii wide
                        $string36 = /RustDesk_install\.bat/ nocase ascii wide
                        $string37 = /rustdesk_portable\.exe/ nocase ascii wide
                        $string38 = /RustDesk_rCURRENT\.log/ nocase ascii wide
                        $string39 = /RustDesk_uninstall\.bat/ nocase ascii wide
                        $string40 = /RustDeskIddDriver\.cer/ nocase ascii wide
                        $string41 = /RustDeskIddDriver\.dll/ nocase ascii wide
                        $string42 = /rustdesk\-portable\-packer\.exe/ nocase ascii wide
                        $string43 = "sc start RustDesk" nocase ascii wide
                        $string44 = "sc stop RustDesk" nocase ascii wide
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
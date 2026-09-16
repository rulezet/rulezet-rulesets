rule MEGAsync
{
    meta:
        description = "Detection patterns for the tool 'MEGAsync' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MEGAsync"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\smegasync\.exe/ nocase ascii wide
                        $string2 = /\sMEGAsyncSetup32\.exe/ nocase ascii wide
                        $string3 = /\sMEGAsyncSetup64\.exe/ nocase ascii wide
                        $string4 = /\.api\.mega\.co\.nz/ nocase ascii wide
                        $string5 = /\.static\.mega\.co\.nz/ nocase ascii wide
                        $string6 = /\/megasync\.exe/ nocase ascii wide
                        $string7 = /\/MEGAsyncSetup32\.exe/ nocase ascii wide
                        $string8 = /\/MEGAsyncSetup64\.exe/ nocase ascii wide
                        $string9 = /\[megaapi_impl\.cpp\:/ nocase ascii wide
                        $string10 = /\[megaclient\.cpp\:/ nocase ascii wide
                        $string11 = /\\appdata\\local\\megasync\\/ nocase ascii wide
                        $string12 = /\\ContextMenuHandlers\\MEGA\s\(Context\smenu\)/ nocase ascii wide
                        $string13 = /\\CurrentVersion\\App\sPaths\\MEGAsync/ nocase ascii wide
                        $string14 = /\\CurrentVersion\\Uninstall\\MEGAsync/ nocase ascii wide
                        $string15 = /\\MEGA\sWebsite\.lnk/ nocase ascii wide
                        $string16 = /\\MEGA\sWebsite\.url/ nocase ascii wide
                        $string17 = /\\megaclient_statecache.{0,100}\.db/ nocase ascii wide
                        $string18 = /\\megaclient_syncconfig_/ nocase ascii wide
                        $string19 = /\\megalimited\-megasync_/ nocase ascii wide
                        $string20 = /\\MEGAprivacyMEGAsync/ nocase ascii wide
                        $string21 = /\\MEGAsync\.cfg/ nocase ascii wide
                        $string22 = /\\megasync\.exe/ nocase ascii wide
                        $string23 = /\\MEGAsync\.lnk/ nocase ascii wide
                        $string24 = /\\megasync\.lock/ nocase ascii wide
                        $string25 = /\\MEGAsync\.log/ nocase ascii wide
                        $string26 = /\\megasync\.version/ nocase ascii wide
                        $string27 = /\\MEGAsyncSetup32\.exe/ nocase ascii wide
                        $string28 = /\\MEGAsyncSetup64\.exe/ nocase ascii wide
                        $string29 = /\\MEGAupdater\.exe/ nocase ascii wide
                        $string30 = /\\ProgramData\\megatmp\.M1\.txt/ nocase ascii wide
                        $string31 = /\\ProgramData\\megatmp\.M2\.txt/ nocase ascii wide
                        $string32 = /\\ShellIconOverlayIdentifiers\\_\sMEGA\s\(Pending\)/ nocase ascii wide
                        $string33 = /\\ShellIconOverlayIdentifiers\\_\sMEGA\s\(Synced\)/ nocase ascii wide
                        $string34 = /\\ShellIconOverlayIdentifiers\\_\sMEGA\s\(Syncing\)/ nocase ascii wide
                        $string35 = /\\Start\sMenu\\Programs\\MEGAsync\\/ nocase ascii wide
                        $string36 = /\\StartupTNotiMEGAsync\.lnk/ nocase ascii wide
                        $string37 = "'Company'>Mega Limited</Data>" nocase ascii wide
                        $string38 = /https\:\/\/mega\.nz\/linux\/repo\//
                        $string39 = "MEGAsync Update Task" nocase ascii wide
                        $string40 = /MEGAsync\.exe\s\// nocase ascii wide
                        $string41 = /MEGASYNC\.EXE\-.{0,100}\.pf/ nocase ascii wide
                        $string42 = /MEGAsync\\ShellExtX64\.dll/ nocase ascii wide
                        $string43 = /megasync\-CentOS_.{0,100}\.x86_64\.rpm/ nocase ascii wide
                        $string44 = /megasync\-CentOS_.{0,100}\.x86_64\.rpm/ nocase ascii wide
                        $string45 = /megasync\-Debian_.{0,100}_amd64\.deb/ nocase ascii wide
                        $string46 = /megasync\-Fedora_.{0,100}\.x86_64\.rpm/ nocase ascii wide
                        $string47 = /megasync\-openSUSE_Leap_.{0,100}\.x86_64\.rpm/ nocase ascii wide
                        $string48 = /megasync\-Raspbian_.{0,100}_armhf\.deb/ nocase ascii wide
                        $string49 = /MEGAsyncSetup32_.{0,100}_RC3\.exe/ nocase ascii wide
                        $string50 = /MEGASYNCSETUP64\.EXE\-.{0,100}\.pf/ nocase ascii wide
                        $string51 = /MEGAsyncSetup64_.{0,100}_RC3\.exe/ nocase ascii wide
                        $string52 = /MEGAsyncSetupArm64\.dmg/ nocase ascii wide
                        $string53 = /megasync\-x86_64\.pkg/ nocase ascii wide
                        $string54 = /megasync\-xUbuntu_.{0,100}_amd64\.deb/ nocase ascii wide
                        $string55 = "'Product'>MEGAsync</Data>" nocase ascii wide
                        $string56 = /ReferrerUrl\=https\:\/\/mega\.io\// nocase ascii wide
                        $string57 = "'Signature'>Mega Limited</Data>" nocase ascii wide
                        $string58 = /Windows\\System32\\Tasks\\MEGA/ nocase ascii wide
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
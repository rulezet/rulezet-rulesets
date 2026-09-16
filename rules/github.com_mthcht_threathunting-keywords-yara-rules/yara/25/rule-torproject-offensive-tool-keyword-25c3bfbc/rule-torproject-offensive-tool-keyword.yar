rule rule_torproject_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'torproject' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "torproject"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_torproject_offensive_tool_keyword = /\s\.\/tor\.keyring\s/
                        $string2_torproject_offensive_tool_keyword = /\s\.\\tor\.keyring\s/ nocase ascii wide
                        $string3_torproject_offensive_tool_keyword = /\s\-\-DataDirectory\s.{0,100}\s\-\-CookieAuthentication\s.{0,100}\s\-\-DisableNetwork\s.{0,100}\s\-\-hush\s\-\-SocksPort\s.{0,100}\s\-f\s.{0,100}\s\-\-ControlPort\s.{0,100}\s\-\-ControlPortWriteToFile\s/ nocase ascii wide
                        $string4_torproject_offensive_tool_keyword = /\.torproject\.org\/.{0,100}\/download\/tor\// nocase ascii wide
                        $string5_torproject_offensive_tool_keyword = /\/tor\-0\..{0,100}\.tar\.gz/ nocase ascii wide
                        $string6_torproject_offensive_tool_keyword = /\/torbrowser\-install\-.{0,100}\.exe\s\s/
                        $string7_torproject_offensive_tool_keyword = /\/tor\-browser\-linux.{0,100}\./
                        $string8_torproject_offensive_tool_keyword = /\/tor\-browser\-osx64.{0,100}\./ nocase ascii wide
                        $string9_torproject_offensive_tool_keyword = /\/tor\-browser\-win32.{0,100}\./ nocase ascii wide
                        $string10_torproject_offensive_tool_keyword = /\/tor\-browser\-win64.{0,100}\./ nocase ascii wide
                        $string11_torproject_offensive_tool_keyword = "/tor-package-archive/" nocase ascii wide
                        $string12_torproject_offensive_tool_keyword = /\\AppData\\Local\\Temp\\tor\s\-\-/ nocase ascii wide
                        $string13_torproject_offensive_tool_keyword = /\\Temp\\tor\\control\-port\-/ nocase ascii wide
                        $string14_torproject_offensive_tool_keyword = /\\Temp\\tor\\torrc\-/ nocase ascii wide
                        $string15_torproject_offensive_tool_keyword = /\\tor\.exe/ nocase ascii wide
                        $string16_torproject_offensive_tool_keyword = /\\torbrowser\-install\-.{0,100}\.exe\s\s/ nocase ascii wide
                        $string17_torproject_offensive_tool_keyword = /\\tor\-browser\-win32.{0,100}\./ nocase ascii wide
                        $string18_torproject_offensive_tool_keyword = /\\tor\-browser\-win64.{0,100}\./ nocase ascii wide
                        $string19_torproject_offensive_tool_keyword = /archive\.torproject\.org/ nocase ascii wide
                        $string20_torproject_offensive_tool_keyword = /deb\.torproject\.org\/torproject\.org\/.{0,100}\.asc/ nocase ascii wide
                        $string21_torproject_offensive_tool_keyword = "dnf install tor -y"
                        $string22_torproject_offensive_tool_keyword = /http\:\/\/.{0,100}\.onion/ nocase ascii wide
                        $string23_torproject_offensive_tool_keyword = /http\:\/\/.{0,100}\.tor2web/ nocase ascii wide
                        $string24_torproject_offensive_tool_keyword = /http\:\/\/.{0,100}\.torlink/ nocase ascii wide
                        $string25_torproject_offensive_tool_keyword = /https\:\/\/.{0,100}\.onion/ nocase ascii wide
                        $string26_torproject_offensive_tool_keyword = /https\:\/\/.{0,100}\.tor2web/ nocase ascii wide
                        $string27_torproject_offensive_tool_keyword = /https\:\/\/.{0,100}\.torlink/ nocase ascii wide
                        $string28_torproject_offensive_tool_keyword = /install\stor\sdeb\.torproject\.org\-keyring/
                        $string29_torproject_offensive_tool_keyword = /rpm\.torproject\.org\/.{0,100}public_gpg\.key/ nocase ascii wide
                        $string30_torproject_offensive_tool_keyword = /taskkill\s\/IM\stor\.exe\s\/F/ nocase ascii wide
                        $string31_torproject_offensive_tool_keyword = "tor --DataDirectory " nocase ascii wide
                        $string32_torproject_offensive_tool_keyword = /TorBrowser\-.{0,100}macos_ALL\.dmg/ nocase ascii wide
                        $string33_torproject_offensive_tool_keyword = /torbrowser\-install\-.{0,100}_ALL\.exe/ nocase ascii wide
                        $string34_torproject_offensive_tool_keyword = /torbrowser\-install\-win.{0,100}\.exe/ nocase ascii wide
                        $string35_torproject_offensive_tool_keyword = "torbrowser-install-win64" nocase ascii wide
                        $string36_torproject_offensive_tool_keyword = /tor\-browser\-linux.{0,100}_ALL\.tar\.xz/
                        $string37_torproject_offensive_tool_keyword = /torproject\.org\/dist\/torbrowser\/.{0,100}\./ nocase ascii wide
                        $string38_torproject_offensive_tool_keyword = /torproject\.org\/download\/download\// nocase ascii wide
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
rule rule_Venom_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Venom' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Venom"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Venom_offensive_tool_keyword = /\sport_reuse\.py/ nocase ascii wide
                        $string2_Venom_offensive_tool_keyword = " --string 'venomcoming' " nocase ascii wide
                        $string3_Venom_offensive_tool_keyword = " --string 'venomleaving' " nocase ascii wide
                        $string4_Venom_offensive_tool_keyword = /\/port_reuse\.py/ nocase ascii wide
                        $string5_Venom_offensive_tool_keyword = /\/Venom\.git/ nocase ascii wide
                        $string6_Venom_offensive_tool_keyword = /\/Venom\.v1\.0\.1\.7z/ nocase ascii wide
                        $string7_Venom_offensive_tool_keyword = /\/Venom\.v1\.0\.2\.7z/ nocase ascii wide
                        $string8_Venom_offensive_tool_keyword = /\/Venom\.v1\.0\.7z/ nocase ascii wide
                        $string9_Venom_offensive_tool_keyword = /\/Venom\.v1\.1\.0\.7z/ nocase ascii wide
                        $string10_Venom_offensive_tool_keyword = "/Venom/tarball/v" nocase ascii wide
                        $string11_Venom_offensive_tool_keyword = "/Venom/zipball/v" nocase ascii wide
                        $string12_Venom_offensive_tool_keyword = /\\port_reuse\.py/ nocase ascii wide
                        $string13_Venom_offensive_tool_keyword = /\\Venom\.v1\.0\.1\.7z/ nocase ascii wide
                        $string14_Venom_offensive_tool_keyword = /\\Venom\.v1\.0\.2\.7z/ nocase ascii wide
                        $string15_Venom_offensive_tool_keyword = /\\Venom\.v1\.0\.7z/ nocase ascii wide
                        $string16_Venom_offensive_tool_keyword = /\\Venom\.v1\.1\.0\.7z/ nocase ascii wide
                        $string17_Venom_offensive_tool_keyword = "37da8267b295caeca8fadb13206ba1c498a7012673430c5d856fe93862446a28" nocase ascii wide
                        $string18_Venom_offensive_tool_keyword = "52907aebc7d2c6534099d149e61bf294b0ddf7d4e814a72b3621e3a829f83c97" nocase ascii wide
                        $string19_Venom_offensive_tool_keyword = /admin_macos_x64\s\-rhost\s.{0,100}\s\-rport\s/ nocase ascii wide
                        $string20_Venom_offensive_tool_keyword = /agent\.exe\s\-lhost\s.{0,100}\s\-reuse\-port\s/ nocase ascii wide
                        $string21_Venom_offensive_tool_keyword = "agent_linux_x64 -lport "
                        $string22_Venom_offensive_tool_keyword = /agent_linux_x64\s\-rhost\s.{0,100}\s\-rport\s/
                        $string23_Venom_offensive_tool_keyword = "Venom Admin Node Start" nocase ascii wide
                        $string24_Venom_offensive_tool_keyword = /Venom\\agent\\agent\.go/ nocase ascii wide
                        $string25_Venom_offensive_tool_keyword = "You can execute commands in this shell :D" nocase ascii wide
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
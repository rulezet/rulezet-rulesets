rule rule_elevationstation_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'elevationstation' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "elevationstation"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_elevationstation_offensive_tool_keyword = /\.exe\s\-uac/ nocase ascii wide
                        $string2_elevationstation_offensive_tool_keyword = /\/elevateit\.bat/ nocase ascii wide
                        $string3_elevationstation_offensive_tool_keyword = /\\\\\\\\\.\\\\pipe\\\\warpzone8/ nocase ascii wide
                        $string4_elevationstation_offensive_tool_keyword = /\\\\\\\\127\.0\.0\.1\\\\pipe\\\\warpzone8/ nocase ascii wide
                        $string5_elevationstation_offensive_tool_keyword = /\\elevateit\.bat/ nocase ascii wide
                        $string6_elevationstation_offensive_tool_keyword = /cmd\.exe\s\/c\ssc\sstart\splumber/ nocase ascii wide
                        $string7_elevationstation_offensive_tool_keyword = /easinvoker\.exe.{0,100}System32/ nocase ascii wide
                        $string8_elevationstation_offensive_tool_keyword = /elevationstation\.cpp/ nocase ascii wide
                        $string9_elevationstation_offensive_tool_keyword = /elevationstation\.exe/ nocase ascii wide
                        $string10_elevationstation_offensive_tool_keyword = /elevationstation\.git/ nocase ascii wide
                        $string11_elevationstation_offensive_tool_keyword = /elevationstation\.sln/ nocase ascii wide
                        $string12_elevationstation_offensive_tool_keyword = "elevationstation-main" nocase ascii wide
                        $string13_elevationstation_offensive_tool_keyword = /github\.com\/g3tsyst3m/ nocase ascii wide
                        $string14_elevationstation_offensive_tool_keyword = /n0de\.exe.{0,100}elevationstation/ nocase ascii wide
                        $string15_elevationstation_offensive_tool_keyword = /sc\screate\splumber.{0,100}warpzoneclient/ nocase ascii wide
                        $string16_elevationstation_offensive_tool_keyword = "sc delete plumber" nocase ascii wide
                        $string17_elevationstation_offensive_tool_keyword = /tokenprivs\.cpp/ nocase ascii wide
                        $string18_elevationstation_offensive_tool_keyword = /tokenprivs\.exe/ nocase ascii wide
                        $string19_elevationstation_offensive_tool_keyword = /uac_easinvoker\./ nocase ascii wide
                        $string20_elevationstation_offensive_tool_keyword = "uacbypass_files" nocase ascii wide
                        $string21_elevationstation_offensive_tool_keyword = /users\\\\public\\\\elevationstation\.js/ nocase ascii wide
                        $string22_elevationstation_offensive_tool_keyword = /users\\\\usethis\\\\NewFile\.txt/ nocase ascii wide
                        $string23_elevationstation_offensive_tool_keyword = /warpzoneclient\.cpp/ nocase ascii wide
                        $string24_elevationstation_offensive_tool_keyword = /warpzoneclient\.exe/ nocase ascii wide
                        $string25_elevationstation_offensive_tool_keyword = /warpzoneclient\.exe/ nocase ascii wide
                        $string26_elevationstation_offensive_tool_keyword = /warpzoneclient\.sln/ nocase ascii wide
                        $string27_elevationstation_offensive_tool_keyword = /warpzoneclient\.vcxproj/ nocase ascii wide
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
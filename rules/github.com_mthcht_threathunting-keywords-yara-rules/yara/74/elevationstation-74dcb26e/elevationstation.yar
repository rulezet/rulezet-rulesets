rule elevationstation
{
    meta:
        description = "Detection patterns for the tool 'elevationstation' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "elevationstation"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe\s\-uac/ nocase ascii wide
                        $string2 = /\/elevateit\.bat/ nocase ascii wide
                        $string3 = /\\\\\\\\\.\\\\pipe\\\\warpzone8/ nocase ascii wide
                        $string4 = /\\\\\\\\127\.0\.0\.1\\\\pipe\\\\warpzone8/ nocase ascii wide
                        $string5 = /\\elevateit\.bat/ nocase ascii wide
                        $string6 = /cmd\.exe\s\/c\ssc\sstart\splumber/ nocase ascii wide
                        $string7 = /easinvoker\.exe.{0,100}System32/ nocase ascii wide
                        $string8 = /elevationstation\.cpp/ nocase ascii wide
                        $string9 = /elevationstation\.exe/ nocase ascii wide
                        $string10 = /elevationstation\.git/ nocase ascii wide
                        $string11 = /elevationstation\.sln/ nocase ascii wide
                        $string12 = "elevationstation-main" nocase ascii wide
                        $string13 = /github\.com\/g3tsyst3m/ nocase ascii wide
                        $string14 = /n0de\.exe.{0,100}elevationstation/ nocase ascii wide
                        $string15 = /sc\screate\splumber.{0,100}warpzoneclient/ nocase ascii wide
                        $string16 = "sc delete plumber" nocase ascii wide
                        $string17 = /tokenprivs\.cpp/ nocase ascii wide
                        $string18 = /tokenprivs\.exe/ nocase ascii wide
                        $string19 = /uac_easinvoker\./ nocase ascii wide
                        $string20 = "uacbypass_files" nocase ascii wide
                        $string21 = /users\\\\public\\\\elevationstation\.js/ nocase ascii wide
                        $string22 = /users\\\\usethis\\\\NewFile\.txt/ nocase ascii wide
                        $string23 = /warpzoneclient\.cpp/ nocase ascii wide
                        $string24 = /warpzoneclient\.exe/ nocase ascii wide
                        $string25 = /warpzoneclient\.exe/ nocase ascii wide
                        $string26 = /warpzoneclient\.sln/ nocase ascii wide
                        $string27 = /warpzoneclient\.vcxproj/ nocase ascii wide
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
rule softperfect_networkscanner
{
    meta:
        description = "Detection patterns for the tool 'softperfect networkscanner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "softperfect networkscanner"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\s\/config\:netscan\.xml\s/ nocase ascii wide
                        $string2 = /\snetscan\.exe\s/ nocase ascii wide
                        $string3 = /\snetscan64\.exe\s/ nocase ascii wide
                        $string4 = /\.exe\s.{0,100}\s\/hide\s.{0,100}\s\/range\:.{0,100}\s\/auto\:.{0,100}\./ nocase ascii wide
                        $string5 = /\.exe\s\/hide\s\/range\:all/ nocase ascii wide
                        $string6 = /\.exe\s\/wakeall/ nocase ascii wide
                        $string7 = /\/netscan\.exe/ nocase ascii wide
                        $string8 = /\/netscan_linux\.tar\.gz/
                        $string9 = /\/netscan_macos\.dmg/ nocase ascii wide
                        $string10 = /\/netscan_setup\.exe/ nocase ascii wide
                        $string11 = /\/netscan64\.exe/ nocase ascii wide
                        $string12 = /\\AppData\\Roaming\\SoftPerfect\sNetwork\sScanner/ nocase ascii wide
                        $string13 = /\\netscan\.dbm\-journal/ nocase ascii wide
                        $string14 = /\\netscan\.exe/ nocase ascii wide
                        $string15 = /\\netscan_linux\.tar\.gz/ nocase ascii wide
                        $string16 = /\\netscan_portable\.zip/ nocase ascii wide
                        $string17 = /\\netscan_portable\\/ nocase ascii wide
                        $string18 = /\\netscan_setup\.exe/ nocase ascii wide
                        $string19 = /\\netscan_setup\.tmp/ nocase ascii wide
                        $string20 = /\\netscan64\.exe/ nocase ascii wide
                        $string21 = /\\SoftPerfect\sNetwork\sScanner\\/ nocase ascii wide
                        $string22 = /\<Data\sName\=\\"RelativeTargetName\\"\>delete\.me\</ nocase ascii wide
                        $string23 = ">SoftPerfect Network Scanner<" nocase ascii wide
                        $string24 = "87e8486846df3005c1b481b1c5205f661b715addfda262f56d2a41892126b399" nocase ascii wide
                        $string25 = /https\:\/\/www\.softperfect\.com\/download\/files\/netscan/ nocase ascii wide
                        $string26 = /https\:\/\/www\.softperfect\.com\/products\/networkscanner\/\?from\=nver/ nocase ascii wide
                        $string27 = /netscan\.exe\s\// nocase ascii wide
                        $string28 = /netscan_portable\.zip/ nocase ascii wide
                        $string29 = /SoftPerfect_.{0,100}Patch_Keygen_v2.{0,100}\.exe/ nocase ascii wide
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
rule rule_mshta_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'mshta' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mshta"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_mshta_greyware_tool_keyword = /forfiles\.exe.{0,100}\s\/p\s.{0,100}\s\/m\s.{0,100}\s\/c\s.{0,100}powershell\s\.\smshta/ nocase ascii wide
                        $string2_mshta_greyware_tool_keyword = /mshta\s\\"C\:\\Users\\Public\\/ nocase ascii wide
                        $string3_mshta_greyware_tool_keyword = /mshta\shttp.{0,100}\.hta/ nocase ascii wide
                        $string4_mshta_greyware_tool_keyword = /mshta\shttps\:\/\/tinyurl\.com\// nocase ascii wide
                        $string5_mshta_greyware_tool_keyword = /mshta\sjavascript\:.{0,100}script\:https\:/ nocase ascii wide
                        $string6_mshta_greyware_tool_keyword = /mshta\sjavascript\:a\=\(GetObject\(\\"script\:http.{0,100}\.sct.{0,100}\)\)\.Exec\(\)\;close\(\)\;/ nocase ascii wide
                        $string7_mshta_greyware_tool_keyword = /mshta\svbscript\:Close\(Execute\(.{0,100}script\:https\:\/\/.{0,100}\.sct/ nocase ascii wide
                        $string8_mshta_greyware_tool_keyword = /mshta\.exe\shttps\:\/\/tinyurl\.com\// nocase ascii wide
                        $string9_mshta_greyware_tool_keyword = /mshta\.exe\sjavascript\:a\=\(GetObject\(\\"script\:http.{0,100}\.sct.{0,100}\)\)\.Exec\(\)\;close\(\)\;/ nocase ascii wide
                        $string10_mshta_greyware_tool_keyword = /mshta\.exe.{0,100}\s\\"C\:\\Users\\Public\\/ nocase ascii wide
                        $string11_mshta_greyware_tool_keyword = /mshta\.exe.{0,100}\shttp\:\/\// nocase ascii wide
                        $string12_mshta_greyware_tool_keyword = /mshta\.exe.{0,100}\shttps\:\/\// nocase ascii wide
                        $string13_mshta_greyware_tool_keyword = /mshta\.exe.{0,100}\sjavascript\:.{0,100}script\:https\:/ nocase ascii wide
                        $string14_mshta_greyware_tool_keyword = /mshta\.exe.{0,100}\svbscript\:Close\(Execute\(.{0,100}script\:https\:\/\/.{0,100}\.sct/ nocase ascii wide
                        $string15_mshta_greyware_tool_keyword = /mshta\.exe.{0,100}I\sam\snot\sa\srobot\s\-\sreCAPTCHA\sVerification\sID\:\s/ nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
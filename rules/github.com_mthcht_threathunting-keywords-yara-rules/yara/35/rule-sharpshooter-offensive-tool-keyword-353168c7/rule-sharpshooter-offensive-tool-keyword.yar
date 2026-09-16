rule rule_SharpShooter_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpShooter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpShooter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpShooter_offensive_tool_keyword = /\samsikiller\.py/ nocase ascii wide
                        $string2_SharpShooter_offensive_tool_keyword = " --com xslremote --awlurl " nocase ascii wide
                        $string3_SharpShooter_offensive_tool_keyword = /\s\-\-dotnetver\s.{0,100}\s\-\-payload\s.{0,100}\s\-\-sandbox\s/ nocase ascii wide
                        $string4_SharpShooter_offensive_tool_keyword = /\s\-\-payload\s.{0,100}\s\-\-output\s.{0,100}\s\-\-rawscfile\s.{0,100}\s\-\-smuggle\s/ nocase ascii wide
                        $string5_SharpShooter_offensive_tool_keyword = /\s\-\-rawscfile\s\.\/x86payload\.bin/
                        $string6_SharpShooter_offensive_tool_keyword = " --smuggle --template mcafee --com " nocase ascii wide
                        $string7_SharpShooter_offensive_tool_keyword = /\s\-\-stageless\s\-\-dotnetver\s.{0,100}\s\-\-payload\s/ nocase ascii wide
                        $string8_SharpShooter_offensive_tool_keyword = /\/amsikiller\.py/ nocase ascii wide
                        $string9_SharpShooter_offensive_tool_keyword = /\/SharpShooter\.git/ nocase ascii wide
                        $string10_SharpShooter_offensive_tool_keyword = /\\amsikiller\.py/ nocase ascii wide
                        $string11_SharpShooter_offensive_tool_keyword = /\\SharpShooter\./ nocase ascii wide
                        $string12_SharpShooter_offensive_tool_keyword = /\\sharpshooter\.js/ nocase ascii wide
                        $string13_SharpShooter_offensive_tool_keyword = /\\sharpshooter\.vba/ nocase ascii wide
                        $string14_SharpShooter_offensive_tool_keyword = /\\sharpshooter\.vbs/ nocase ascii wide
                        $string15_SharpShooter_offensive_tool_keyword = /\\SharpShooter\-main/ nocase ascii wide
                        $string16_SharpShooter_offensive_tool_keyword = /\\sharpshooterv4\.js/ nocase ascii wide
                        $string17_SharpShooter_offensive_tool_keyword = /\\sharpshooterv4\.vba/ nocase ascii wide
                        $string18_SharpShooter_offensive_tool_keyword = /\\sharpshooterv4\.vbs/ nocase ascii wide
                        $string19_SharpShooter_offensive_tool_keyword = /\\stageless\.vba/ nocase ascii wide
                        $string20_SharpShooter_offensive_tool_keyword = /\\stageless\.vbs/ nocase ascii wide
                        $string21_SharpShooter_offensive_tool_keyword = /\\stagelessv4\.vba/ nocase ascii wide
                        $string22_SharpShooter_offensive_tool_keyword = /\\stagelessv4\.vbs/ nocase ascii wide
                        $string23_SharpShooter_offensive_tool_keyword = "23f017c0041a2164abfe06a03e3ad5b32e002e46d513f314632ed38280de8b14" nocase ascii wide
                        $string24_SharpShooter_offensive_tool_keyword = "286a68fb3a355b790f127b74edb0d084749960ee7b1d9e66c1eb094c14733631" nocase ascii wide
                        $string25_SharpShooter_offensive_tool_keyword = "2d2e0ad0b515712ae445a179701ae0e61d759498bea45c9431ae93c1469e1172" nocase ascii wide
                        $string26_SharpShooter_offensive_tool_keyword = "39556e3779ee1fc2a06c32eff48acd03a01aa0b59bac075ad1457b65a14b3911" nocase ascii wide
                        $string27_SharpShooter_offensive_tool_keyword = "51479ff32cd7f2520a0b252fa3731361c3cc3288d6b0f7831b91a208cd91aaa3" nocase ascii wide
                        $string28_SharpShooter_offensive_tool_keyword = "56598F1C-6D88-4994-A392-AF337ABE5777" nocase ascii wide
                        $string29_SharpShooter_offensive_tool_keyword = "AAEAAAD/////AQAAAAAAAAAEAQAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVy" nocase ascii wide
                        $string30_SharpShooter_offensive_tool_keyword = "AG8AbwB0AGUAcgBBAHMAcwBlAG0AYgBsAHkAAAAAADQACAABAFAAcgBvAGQAdQBjAHQAVgBlAHIA" nocase ascii wide
                        $string31_SharpShooter_offensive_tool_keyword = "AQ0AAAAEAAAACRcAAAAJBgAAAAkWAAAABhoAAAAnU3lzdGVtLlJlZmxlY3Rpb24uQXNzZW1ibHkg" nocase ascii wide
                        $string32_SharpShooter_offensive_tool_keyword = "AwAAAAhEZWxlZ2F0ZQd0YXJnZXQwB21ldGhvZDADAwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXph" nocase ascii wide
                        $string33_SharpShooter_offensive_tool_keyword = /create_awl_payload\(/ nocase ascii wide
                        $string34_SharpShooter_offensive_tool_keyword = /create_com_stager\(/ nocase ascii wide
                        $string35_SharpShooter_offensive_tool_keyword = "dGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5IlN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xk" nocase ascii wide
                        $string36_SharpShooter_offensive_tool_keyword = "LgBkAGwAbAAAAAAASgAVAAEAUAByAG8AZAB1AGMAdABOAGEAbQBlAAAAAABTAGgAYQByAHAAUwBo" nocase ascii wide
                        $string37_SharpShooter_offensive_tool_keyword = "Macro payload cannot be smuggled" nocase ascii wide
                        $string38_SharpShooter_offensive_tool_keyword = "mdsecactivebreach/SharpShooter" nocase ascii wide
                        $string39_SharpShooter_offensive_tool_keyword = /SharpShooter\.py/ nocase ascii wide
                        $string40_SharpShooter_offensive_tool_keyword = "Stageless payloads require the --rawscfile argument" nocase ascii wide
                        $string41_SharpShooter_offensive_tool_keyword = "ZXMARGVidWdnaW5nTW9kZXMAZ2V0X1JlZmVyZW5jZWRBc3NlbWJsaWVzAEdldElQR2xvYmFsUHJv" nocase ascii wide
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
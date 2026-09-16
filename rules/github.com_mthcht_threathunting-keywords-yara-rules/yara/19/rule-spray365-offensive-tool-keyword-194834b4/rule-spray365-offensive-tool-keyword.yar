rule rule_Spray365_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Spray365' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Spray365"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Spray365_offensive_tool_keyword = " --custom_user_agent" nocase ascii wide
                        $string2_Spray365_offensive_tool_keyword = /\sgenerate\saudit\s\-ep\s.{0,100}\-\-passwords_in_userfile/ nocase ascii wide
                        $string3_Spray365_offensive_tool_keyword = /\sgenerate\snormal\s\-ep\s.{0,100}\s\-d\s.{0,100}\s\-u\s.{0,100}\s\-pf\s/ nocase ascii wide
                        $string4_Spray365_offensive_tool_keyword = /\sgenerate\snormal\s\-ep\sex\-plan\.s365\s/ nocase ascii wide
                        $string5_Spray365_offensive_tool_keyword = " --random_user_agent" nocase ascii wide
                        $string6_Spray365_offensive_tool_keyword = " --show_invalid_creds" nocase ascii wide
                        $string7_Spray365_offensive_tool_keyword = /\sspray\s\-ep\sex\-plan\.s365/ nocase ascii wide
                        $string8_Spray365_offensive_tool_keyword = /\.py\sspray\s\-ep\s/ nocase ascii wide
                        $string9_Spray365_offensive_tool_keyword = /\/spray\/spray\.py/ nocase ascii wide
                        $string10_Spray365_offensive_tool_keyword = "/Spray365" nocase ascii wide
                        $string11_Spray365_offensive_tool_keyword = /Spray365\.git/ nocase ascii wide
                        $string12_Spray365_offensive_tool_keyword = /spray365\.py/ nocase ascii wide
                        $string13_Spray365_offensive_tool_keyword = /spray365_results_.{0,100}\.json/ nocase ascii wide
                        $string14_Spray365_offensive_tool_keyword = /\-\-user_file.{0,100}\-\-password_file/ nocase ascii wide
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
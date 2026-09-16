rule rule_ADCSPwn_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ADCSPwn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADCSPwn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ADCSPwn_offensive_tool_keyword = /\.exe\s\-\-adcs\s.{0,100}\s\-\-remote\s/ nocase ascii wide
                        $string2_ADCSPwn_offensive_tool_keyword = /\/ADCSPwn\.git/ nocase ascii wide
                        $string3_ADCSPwn_offensive_tool_keyword = /\\ADCSPwn/ nocase ascii wide
                        $string4_ADCSPwn_offensive_tool_keyword = ">ADCSPwn<" nocase ascii wide
                        $string5_ADCSPwn_offensive_tool_keyword = "0bb4b892f67fdf903ed5e5df2c85c5ccb71669c298736cf24284412de435509a" nocase ascii wide
                        $string6_ADCSPwn_offensive_tool_keyword = "980EF05F-87D1-4A0A-932A-582FB1BC3AC3" nocase ascii wide
                        $string7_ADCSPwn_offensive_tool_keyword = /ADCSPwn\.csproj/ nocase ascii wide
                        $string8_ADCSPwn_offensive_tool_keyword = /ADCSPwn\.exe/ nocase ascii wide
                        $string9_ADCSPwn_offensive_tool_keyword = /ADCSPwn\.sln/ nocase ascii wide
                        $string10_ADCSPwn_offensive_tool_keyword = /ADCSPwn\.zip/ nocase ascii wide
                        $string11_ADCSPwn_offensive_tool_keyword = "ADCSPwn-master" nocase ascii wide
                        $string12_ADCSPwn_offensive_tool_keyword = "bats3c/ADCSPwn" nocase ascii wide
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
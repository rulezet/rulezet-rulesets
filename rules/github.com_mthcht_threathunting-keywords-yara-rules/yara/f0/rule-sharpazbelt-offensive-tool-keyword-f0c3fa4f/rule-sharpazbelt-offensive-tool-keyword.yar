rule rule_SharpAzbelt_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpAzbelt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpAzbelt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpAzbelt_offensive_tool_keyword = /\/SharpAzbelt\.git/ nocase ascii wide
                        $string2_SharpAzbelt_offensive_tool_keyword = /\[\!\]\s\s\s\sFailed\sto\senumerate\sCredman\:/ nocase ascii wide
                        $string3_SharpAzbelt_offensive_tool_keyword = /\[i\]\sAAD\sJoin\:.{0,100}enumerate/ nocase ascii wide
                        $string4_SharpAzbelt_offensive_tool_keyword = /\[i\]\sCredman\:.{0,100}Credential\sBlob\sDecrypted/ nocase ascii wide
                        $string5_SharpAzbelt_offensive_tool_keyword = /\\SharpAzbelt\.csproj/ nocase ascii wide
                        $string6_SharpAzbelt_offensive_tool_keyword = /\\SharpAzbelt\.exe/ nocase ascii wide
                        $string7_SharpAzbelt_offensive_tool_keyword = /\\SharpAzbelt\.sln/ nocase ascii wide
                        $string8_SharpAzbelt_offensive_tool_keyword = "57D4D4F4-F083-47A3-AE33-AE2500ABA3B6" nocase ascii wide
                        $string9_SharpAzbelt_offensive_tool_keyword = /ParseMSALCache.{0,100}\.azure\\msal_token_cache\.bin/ nocase ascii wide
                        $string10_SharpAzbelt_offensive_tool_keyword = /ParseMSALCache.{0,100}Appdata\\Local\\\.IdentityService\\msal\.cache/ nocase ascii wide
                        $string11_SharpAzbelt_offensive_tool_keyword = "redskal/SharpAzbelt" nocase ascii wide
                        $string12_SharpAzbelt_offensive_tool_keyword = "SharpAzbelt-main" nocase ascii wide
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
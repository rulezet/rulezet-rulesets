rule rule_GoFetch_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GoFetch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GoFetch"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GoFetch_offensive_tool_keyword = /\s\-pathToBloodHoundGraph\s.{0,100}\s\-pathToOutputGoFetchPath\s.{0,100}\s\-pathToAdditionalPayload\s/ nocase ascii wide
                        $string2_GoFetch_offensive_tool_keyword = /\s\-PathToGraph\s.{0,100}\.json\s\-PathToPayload\s.{0,100}\.exe/ nocase ascii wide
                        $string3_GoFetch_offensive_tool_keyword = /\/gofetch\.exe/ nocase ascii wide
                        $string4_GoFetch_offensive_tool_keyword = /\/GoFetch\.git/ nocase ascii wide
                        $string5_GoFetch_offensive_tool_keyword = /\\gofetch\.exe/ nocase ascii wide
                        $string6_GoFetch_offensive_tool_keyword = /\\GoFetchLog\.log/ nocase ascii wide
                        $string7_GoFetch_offensive_tool_keyword = /\\GoFetch\-main/ nocase ascii wide
                        $string8_GoFetch_offensive_tool_keyword = /\\PsExecLog\.log/ nocase ascii wide
                        $string9_GoFetch_offensive_tool_keyword = "1615016050f681f61f692ef54d34a26911587fff98fa6ee1f945f1ecd04e2705"
                        $string10_GoFetch_offensive_tool_keyword = "7c37604dd86dc2ce14b352c8df0c4230ab3a1887ef73349806b0e7c15025843c" nocase ascii wide
                        $string11_GoFetch_offensive_tool_keyword = "BloodHoundGraphToGoFetchPath" nocase ascii wide
                        $string12_GoFetch_offensive_tool_keyword = "GoFetchAD/GoFetch" nocase ascii wide
                        $string13_GoFetch_offensive_tool_keyword = "Invoke-GoFetch" nocase ascii wide
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
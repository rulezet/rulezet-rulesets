rule rule_SingleDose_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SingleDose' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SingleDose"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SingleDose_offensive_tool_keyword = /\/SingleDose\.git/ nocase ascii wide
                        $string2_SingleDose_offensive_tool_keyword = /\\Payloads\\.{0,100}\.bin/ nocase ascii wide
                        $string3_SingleDose_offensive_tool_keyword = /\\PoisonTendy\\Invokes\\/ nocase ascii wide
                        $string4_SingleDose_offensive_tool_keyword = /\\SingleDose\.csproj/ nocase ascii wide
                        $string5_SingleDose_offensive_tool_keyword = /\\SingleDose\.exe/ nocase ascii wide
                        $string6_SingleDose_offensive_tool_keyword = /\\SingleDose\.sln/ nocase ascii wide
                        $string7_SingleDose_offensive_tool_keyword = /\\SingleDose\-main\.zip/ nocase ascii wide
                        $string8_SingleDose_offensive_tool_keyword = "4D7AEF0B-5AA6-4AE5-971E-7141AA1FDAFC" nocase ascii wide
                        $string9_SingleDose_offensive_tool_keyword = "5FAC3991-D4FD-4227-B73D-BEE34EB89987" nocase ascii wide
                        $string10_SingleDose_offensive_tool_keyword = "C0E67E76-1C78-4152-9F79-FA27B4F7CCCA" nocase ascii wide
                        $string11_SingleDose_offensive_tool_keyword = /PoisonTendy\.dll/ nocase ascii wide
                        $string12_SingleDose_offensive_tool_keyword = "Wra7h/SingleDose" nocase ascii wide
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
rule rule_bypassUAC_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bypassUAC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bypassUAC"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_bypassUAC_offensive_tool_keyword = /\s\-OutputAssembly\s\\"sl0p\.dll\\"/ nocase ascii wide
                        $string2_bypassUAC_offensive_tool_keyword = /\sUAC\-Bypass\.ps1/ nocase ascii wide
                        $string3_bypassUAC_offensive_tool_keyword = /\/sl0p\.dll/ nocase ascii wide
                        $string4_bypassUAC_offensive_tool_keyword = /\/UAC\-Bypass\.ps1/ nocase ascii wide
                        $string5_bypassUAC_offensive_tool_keyword = /\\iscsicpl_bypassUAC/ nocase ascii wide
                        $string6_bypassUAC_offensive_tool_keyword = /\\sl0p\.dll/ nocase ascii wide
                        $string7_bypassUAC_offensive_tool_keyword = /\\UAC\-Bypass\.ps1/ nocase ascii wide
                        $string8_bypassUAC_offensive_tool_keyword = "0acffe2314b3329c3a984cd5b402bf17e1de0305b38d9e1daa5f566182dbef6f" nocase ascii wide
                        $string9_bypassUAC_offensive_tool_keyword = "4494BDD20D3FA171BF25A733B6755A6BE88F97BAEBB98820A385CE2D4BE9BE0F" nocase ascii wide
                        $string10_bypassUAC_offensive_tool_keyword = "4d3bae5b-eb71-413b-adb2-a58f1fa2ad64" nocase ascii wide
                        $string11_bypassUAC_offensive_tool_keyword = "4e3beb361e85dab6b6f15e0c72e8e47376d0b678dd7ba537c24a5e0e5085ea7c" nocase ascii wide
                        $string12_bypassUAC_offensive_tool_keyword = "804E7688C41C080042845DEA6461DAE99DAB16204788E4BEE1C7476AD1280674" nocase ascii wide
                        $string13_bypassUAC_offensive_tool_keyword = "8845A8AF-34DC-4EBC-8223-B35F8CC8A900" nocase ascii wide
                        $string14_bypassUAC_offensive_tool_keyword = "Aka    : x0xr00t" nocase ascii wide
                        $string15_bypassUAC_offensive_tool_keyword = "iscsicpl autoelevate DLL Search Order hijacking UAC Bypass" nocase ascii wide
                        $string16_bypassUAC_offensive_tool_keyword = /iscsicpl_BypassUAC_x86\.exe/ nocase ascii wide
                        $string17_bypassUAC_offensive_tool_keyword = /ISecurityEditorUAC_off\.exe/ nocase ascii wide
                        $string18_bypassUAC_offensive_tool_keyword = "Name   : UAC Bypass Win Server 2022" nocase ascii wide
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
rule rule_physmem2profit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'physmem2profit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "physmem2profit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_physmem2profit_offensive_tool_keyword = /\sphysmem2minidump\.py/ nocase ascii wide
                        $string2_physmem2profit_offensive_tool_keyword = /\/label\-date\-lsass\.dmp/ nocase ascii wide
                        $string3_physmem2profit_offensive_tool_keyword = /\/physmem2minidump\.py/ nocase ascii wide
                        $string4_physmem2profit_offensive_tool_keyword = /\/physmem2profit\.git/ nocase ascii wide
                        $string5_physmem2profit_offensive_tool_keyword = /\\physmem2minidump\.py/ nocase ascii wide
                        $string6_physmem2profit_offensive_tool_keyword = /\\physmem2profit\-master/ nocase ascii wide
                        $string7_physmem2profit_offensive_tool_keyword = ">physmem2profit<" nocase ascii wide
                        $string8_physmem2profit_offensive_tool_keyword = "23ecca2af6db4c425ab534b9a738f7ec152c7fcf3c250f3ce9d7f57e6259eac9" nocase ascii wide
                        $string9_physmem2profit_offensive_tool_keyword = "814708C9-2320-42D2-A45F-31E42DA06A94" nocase ascii wide
                        $string10_physmem2profit_offensive_tool_keyword = "cc24850f03dccbd8ee3a372b06b2a77a95e5314bb68d2483b1814935978b7003" nocase ascii wide
                        $string11_physmem2profit_offensive_tool_keyword = "MimikatzStream should be at offset " nocase ascii wide
                        $string12_physmem2profit_offensive_tool_keyword = /output.{0,100}\-lsass\.dmp/ nocase ascii wide
                        $string13_physmem2profit_offensive_tool_keyword = /physmem2profit\.exe/ nocase ascii wide
                        $string14_physmem2profit_offensive_tool_keyword = /Physmem2profit\.sln/ nocase ascii wide
                        $string15_physmem2profit_offensive_tool_keyword = /physmem2profit\-public\.zip/ nocase ascii wide
                        $string16_physmem2profit_offensive_tool_keyword = "source physmem2profit" nocase ascii wide
                        $string17_physmem2profit_offensive_tool_keyword = "WithSecureLabs/physmem2profit" nocase ascii wide
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
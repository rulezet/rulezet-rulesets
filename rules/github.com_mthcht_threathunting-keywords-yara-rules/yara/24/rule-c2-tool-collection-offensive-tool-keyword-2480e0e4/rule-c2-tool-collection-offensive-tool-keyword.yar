rule rule_C2_Tool_Collection_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'C2-Tool-Collection' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "C2-Tool-Collection"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_C2_Tool_Collection_offensive_tool_keyword = "/C2-Tool-Collection/" nocase ascii wide
                        $string2_C2_Tool_Collection_offensive_tool_keyword = /\/SprayAD\.exe/ nocase ascii wide
                        $string3_C2_Tool_Collection_offensive_tool_keyword = /\\SprayAD\.cna/ nocase ascii wide
                        $string4_C2_Tool_Collection_offensive_tool_keyword = /\\SprayAD\.exe/ nocase ascii wide
                        $string5_C2_Tool_Collection_offensive_tool_keyword = /Lapsdump\.cna/ nocase ascii wide
                        $string6_C2_Tool_Collection_offensive_tool_keyword = /Lapsdump\.exe/ nocase ascii wide
                        $string7_C2_Tool_Collection_offensive_tool_keyword = /PetitPotam\.cna/ nocase ascii wide
                        $string8_C2_Tool_Collection_offensive_tool_keyword = /PetitPotam\.exe/ nocase ascii wide
                        $string9_C2_Tool_Collection_offensive_tool_keyword = /PetitPotam\.ps1/ nocase ascii wide
                        $string10_C2_Tool_Collection_offensive_tool_keyword = /PetitPotam\.sln/ nocase ascii wide
                        $string11_C2_Tool_Collection_offensive_tool_keyword = /PetitPotam\.vcxproj/ nocase ascii wide
                        $string12_C2_Tool_Collection_offensive_tool_keyword = /ReflectiveDll\./ nocase ascii wide
                        $string13_C2_Tool_Collection_offensive_tool_keyword = /ReflectiveDLLInjection\./ nocase ascii wide
                        $string14_C2_Tool_Collection_offensive_tool_keyword = /ReflectiveLoader\./ nocase ascii wide
                        $string15_C2_Tool_Collection_offensive_tool_keyword = /SprayAD\.exe\s/ nocase ascii wide
                        $string16_C2_Tool_Collection_offensive_tool_keyword = /TicketToHashcat\.py/ nocase ascii wide
                        $string17_C2_Tool_Collection_offensive_tool_keyword = "Lapsdump " nocase ascii wide
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
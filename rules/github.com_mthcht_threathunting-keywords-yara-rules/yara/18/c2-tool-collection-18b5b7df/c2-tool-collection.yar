rule C2_Tool_Collection
{
    meta:
        description = "Detection patterns for the tool 'C2-Tool-Collection' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "C2-Tool-Collection"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/C2-Tool-Collection/" nocase ascii wide
                        $string2 = /\/SprayAD\.exe/ nocase ascii wide
                        $string3 = /\\SprayAD\.cna/ nocase ascii wide
                        $string4 = /\\SprayAD\.exe/ nocase ascii wide
                        $string5 = /Lapsdump\.cna/ nocase ascii wide
                        $string6 = /Lapsdump\.exe/ nocase ascii wide
                        $string7 = /PetitPotam\.cna/ nocase ascii wide
                        $string8 = /PetitPotam\.exe/ nocase ascii wide
                        $string9 = /PetitPotam\.ps1/ nocase ascii wide
                        $string10 = /PetitPotam\.sln/ nocase ascii wide
                        $string11 = /PetitPotam\.vcxproj/ nocase ascii wide
                        $string12 = /ReflectiveDll\./ nocase ascii wide
                        $string13 = /ReflectiveDLLInjection\./ nocase ascii wide
                        $string14 = /ReflectiveLoader\./ nocase ascii wide
                        $string15 = /SprayAD\.exe\s/ nocase ascii wide
                        $string16 = /TicketToHashcat\.py/ nocase ascii wide
                        $string17 = "Lapsdump " nocase ascii wide
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
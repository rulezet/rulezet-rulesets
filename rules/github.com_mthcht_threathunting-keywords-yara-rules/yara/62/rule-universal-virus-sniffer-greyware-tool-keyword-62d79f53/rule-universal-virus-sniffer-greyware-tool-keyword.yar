rule rule_Universal_Virus_Sniffer_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Universal Virus Sniffer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Universal Virus Sniffer"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Universal_Virus_Sniffer_greyware_tool_keyword = /\/uvs_v415eng\.zip/ nocase ascii wide
                        $string2_Universal_Virus_Sniffer_greyware_tool_keyword = /\\AppData\\Local\\Temp\\.{0,100}\\Doc_ENG\\_Rootkit\sdetection\.txt/ nocase ascii wide
                        $string3_Universal_Virus_Sniffer_greyware_tool_keyword = /\\Update_UVS\.exe/ nocase ascii wide
                        $string4_Universal_Virus_Sniffer_greyware_tool_keyword = /\\uvs_v415eng\.zip/ nocase ascii wide
                        $string5_Universal_Virus_Sniffer_greyware_tool_keyword = "dd90d845a111bc52b3d81dd597c5eaf0ef41d2278383a668f8932d8faefccbda" nocase ascii wide
                        $string6_Universal_Virus_Sniffer_greyware_tool_keyword = /http\:\/\/dsrt\.dyndns\.org\:8888\/uvs_freeupdate_en\.htm/ nocase ascii wide
                        $string7_Universal_Virus_Sniffer_greyware_tool_keyword = /http\:\/\/dsrt\.dyndns\.org\:8888\/uvs_register_en\.htm/ nocase ascii wide
                        $string8_Universal_Virus_Sniffer_greyware_tool_keyword = /PUA\.Win32\.uVirusSniffer\.A/ nocase ascii wide
                        $string9_Universal_Virus_Sniffer_greyware_tool_keyword = "PUA:Win32/Packunwan" nocase ascii wide
                        $string10_Universal_Virus_Sniffer_greyware_tool_keyword = /Universal\.Virus\.Sniffer\.4\.15\.zip/ nocase ascii wide
                        $string11_Universal_Virus_Sniffer_greyware_tool_keyword = "Win32/UniversalVirusSniffer" nocase ascii wide
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
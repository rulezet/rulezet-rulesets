rule rule_DLHell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DLHell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DLHell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DLHell_offensive_tool_keyword = /\sDLHell\.py/ nocase ascii wide
                        $string2_DLHell_offensive_tool_keyword = "## DLHell Main function" nocase ascii wide
                        $string3_DLHell_offensive_tool_keyword = "#Dumps exported function from legit DLL using winedump" nocase ascii wide
                        $string4_DLHell_offensive_tool_keyword = "#Removes previous hijacked dll" nocase ascii wide
                        $string5_DLHell_offensive_tool_keyword = /\.py\s\s\-t\s.{0,100}\.tpe\s\-c\s.{0,100}\.exe.{0,100}\s\-remote\-lib\s.{0,100}\-remote\-target\s/ nocase ascii wide
                        $string6_DLHell_offensive_tool_keyword = /\.py\s\-t\stemplate\.tpe\s\-c\s\'calc\.exe\'/ nocase ascii wide
                        $string7_DLHell_offensive_tool_keyword = /\/DLHell\.git/ nocase ascii wide
                        $string8_DLHell_offensive_tool_keyword = /\/DLHell\.py/ nocase ascii wide
                        $string9_DLHell_offensive_tool_keyword = /\\DLHell\.py/ nocase ascii wide
                        $string10_DLHell_offensive_tool_keyword = /\\DLHell\-main\\/ nocase ascii wide
                        $string11_DLHell_offensive_tool_keyword = "Available ProgIDs and CLSIDs for DLL Hijacking:" nocase ascii wide
                        $string12_DLHell_offensive_tool_keyword = /DLHell\sv2\.0/ nocase ascii wide
                        $string13_DLHell_offensive_tool_keyword = /DLHell\.py\s\-/ nocase ascii wide
                        $string14_DLHell_offensive_tool_keyword = "DLL Hell - DLL Proxifier/Hijacker" nocase ascii wide
                        $string15_DLHell_offensive_tool_keyword = /dump_exported_functions\(library\,dll_orig\)/ nocase ascii wide
                        $string16_DLHell_offensive_tool_keyword = "f47ae40fa2ba9ad689d59f8b755ea68e116c3dd603d6f985a7eff273ce0f381b" nocase ascii wide
                        $string17_DLHell_offensive_tool_keyword = /impacket\.dcerpc\.v5/ nocase ascii wide
                        $string18_DLHell_offensive_tool_keyword = /impacket\.smbconnection/ nocase ascii wide
                        $string19_DLHell_offensive_tool_keyword = /kevin\.tellier\@synacktiv\.com/ nocase ascii wide
                        $string20_DLHell_offensive_tool_keyword = "synacktiv/DLHell" nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
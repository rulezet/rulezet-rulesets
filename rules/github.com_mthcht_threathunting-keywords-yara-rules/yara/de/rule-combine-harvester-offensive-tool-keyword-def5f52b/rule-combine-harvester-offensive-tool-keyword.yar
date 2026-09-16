rule rule_combine_harvester_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'combine_harvester' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "combine_harvester"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_combine_harvester_offensive_tool_keyword = /\/combine_harvester\.git/ nocase ascii wide
                        $string2_combine_harvester_offensive_tool_keyword = /\[X\]\sYour\sharvest\sexploded\:/ nocase ascii wide
                        $string3_combine_harvester_offensive_tool_keyword = /\\combine\.exe/ nocase ascii wide
                        $string4_combine_harvester_offensive_tool_keyword = /\\combine_gui\.exe/ nocase ascii wide
                        $string5_combine_harvester_offensive_tool_keyword = /\\harvest\.cmb/ nocase ascii wide
                        $string6_combine_harvester_offensive_tool_keyword = "23E06BF12C5BE7641EF89F557C3F6600E1F3881F8DCE7279C2112279E7EC3B988E1A85EC350149007DE78CE5566FCBD18F630D2CDB78C76AA06F2B121F0B3701" nocase ascii wide
                        $string7_combine_harvester_offensive_tool_keyword = "combine_harvester-main" nocase ascii wide
                        $string8_combine_harvester_offensive_tool_keyword = "m3f157O/combine_harvester" nocase ascii wide
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
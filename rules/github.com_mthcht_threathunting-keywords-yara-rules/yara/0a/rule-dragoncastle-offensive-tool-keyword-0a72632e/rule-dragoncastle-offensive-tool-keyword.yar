rule rule_DragonCastle_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DragonCastle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DragonCastle"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DragonCastle_offensive_tool_keyword = /\sdragoncastle\.py/ nocase ascii wide
                        $string2_DragonCastle_offensive_tool_keyword = /\s\-target\-ip\s.{0,100}\s\-remote\-dll\s.{0,100}\.dll.{0,100}\s\-local\-dll\s/ nocase ascii wide
                        $string3_DragonCastle_offensive_tool_keyword = /\/DragonCastle\.git/ nocase ascii wide
                        $string4_DragonCastle_offensive_tool_keyword = /\/DragonCastle\.pdb/ nocase ascii wide
                        $string5_DragonCastle_offensive_tool_keyword = /\/dragoncastle\.py/ nocase ascii wide
                        $string6_DragonCastle_offensive_tool_keyword = /\\DragonCastle\.dll/ nocase ascii wide
                        $string7_DragonCastle_offensive_tool_keyword = /\\DragonCastle\.pdb/ nocase ascii wide
                        $string8_DragonCastle_offensive_tool_keyword = /\\DragonCastle\-master\\/ nocase ascii wide
                        $string9_DragonCastle_offensive_tool_keyword = /\\kuhl_m_sekurlsa\.c/ nocase ascii wide
                        $string10_DragonCastle_offensive_tool_keyword = /\\pwned\.txt/ nocase ascii wide
                        $string11_DragonCastle_offensive_tool_keyword = "274F19EC-7CBA-4FC7-80E6-BB41C1FE6728" nocase ascii wide
                        $string12_DragonCastle_offensive_tool_keyword = "DragonCastle - @TheXC3LL" nocase ascii wide
                        $string13_DragonCastle_offensive_tool_keyword = /DragonCastle\.dll/ nocase ascii wide
                        $string14_DragonCastle_offensive_tool_keyword = /dragoncastle\.py\s\-/ nocase ascii wide
                        $string15_DragonCastle_offensive_tool_keyword = "mdsecactivebreach/DragonCastle" nocase ascii wide
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
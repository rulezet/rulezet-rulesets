rule rule_D1rkInject_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'D1rkInject' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "D1rkInject"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_D1rkInject_offensive_tool_keyword = /\/D1rkInject\.git/ nocase ascii wide
                        $string2_D1rkInject_offensive_tool_keyword = /\/MalStuff\.cpp/ nocase ascii wide
                        $string3_D1rkInject_offensive_tool_keyword = /\\D1rkInject\\/ nocase ascii wide
                        $string4_D1rkInject_offensive_tool_keyword = /\\MalStuff\.cpp/ nocase ascii wide
                        $string5_D1rkInject_offensive_tool_keyword = "APT stands for Advanced Persistence Tomato" nocase ascii wide
                        $string6_D1rkInject_offensive_tool_keyword = "BD602C80-47ED-4294-B981-0119D2200DB8" nocase ascii wide
                        $string7_D1rkInject_offensive_tool_keyword = /D1rkInject\.cpp/ nocase ascii wide
                        $string8_D1rkInject_offensive_tool_keyword = /D1rkInject\.exe/ nocase ascii wide
                        $string9_D1rkInject_offensive_tool_keyword = /D1rkInject\.iobj/ nocase ascii wide
                        $string10_D1rkInject_offensive_tool_keyword = /D1rkInject\.log/ nocase ascii wide
                        $string11_D1rkInject_offensive_tool_keyword = /D1rkInject\.sln/ nocase ascii wide
                        $string12_D1rkInject_offensive_tool_keyword = /D1rkInject\.vcxproj/ nocase ascii wide
                        $string13_D1rkInject_offensive_tool_keyword = "D1rkInject-main" nocase ascii wide
                        $string14_D1rkInject_offensive_tool_keyword = "EEC35BCF-E990-4260-828D-2B4F9AC97269" nocase ascii wide
                        $string15_D1rkInject_offensive_tool_keyword = "TheD1rkMtr/D1rkInject" nocase ascii wide
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
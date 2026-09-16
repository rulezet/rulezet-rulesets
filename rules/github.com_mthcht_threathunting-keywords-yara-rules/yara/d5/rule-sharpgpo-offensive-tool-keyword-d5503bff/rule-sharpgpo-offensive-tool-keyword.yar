rule rule_SharpGpo_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpGpo' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpGpo"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpGpo_offensive_tool_keyword = " --Action NewSecurityFiltering --GPOName " nocase ascii wide
                        $string2_SharpGpo_offensive_tool_keyword = " --Action RemoveSecurityFiltering --GPOName " nocase ascii wide
                        $string3_SharpGpo_offensive_tool_keyword = /\.exe\s\-\-Action\sGetGPLink\s\-\-/ nocase ascii wide
                        $string4_SharpGpo_offensive_tool_keyword = /\.exe\s\-\-Action\sGetGPO\s\-\-/ nocase ascii wide
                        $string5_SharpGpo_offensive_tool_keyword = /\.exe\s\-\-Action\sMoveObject\s\-\-/ nocase ascii wide
                        $string6_SharpGpo_offensive_tool_keyword = /\.exe\s\-\-Action\sNewGPLink\s\-\-DN\s/ nocase ascii wide
                        $string7_SharpGpo_offensive_tool_keyword = /\.exe\s\-\-Action\sRemoveGPLink\s\-\-DN\s/ nocase ascii wide
                        $string8_SharpGpo_offensive_tool_keyword = /\.exe\s\-\-Action\sRemoveGPO\s\-\-/ nocase ascii wide
                        $string9_SharpGpo_offensive_tool_keyword = /\.exe\s\-\-Action\sRemoveOU\s\-\-/ nocase ascii wide
                        $string10_SharpGpo_offensive_tool_keyword = /\/SharpGpo\.exe/ nocase ascii wide
                        $string11_SharpGpo_offensive_tool_keyword = /\\SharpGpo\.exe/ nocase ascii wide
                        $string12_SharpGpo_offensive_tool_keyword = /\\SharpGPOAbuse\-master/ nocase ascii wide
                        $string13_SharpGpo_offensive_tool_keyword = ">SharpGPO<" nocase ascii wide
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
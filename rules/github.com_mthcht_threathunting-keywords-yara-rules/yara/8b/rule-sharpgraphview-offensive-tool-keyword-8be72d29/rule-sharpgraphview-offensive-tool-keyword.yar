rule rule_SharpGraphView_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpGraphView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpGraphView"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpGraphView_offensive_tool_keyword = " Invoke-CertToAccessToken -tenant " nocase ascii wide
                        $string2_SharpGraphView_offensive_tool_keyword = /\/SharpGraphView\.git/ nocase ascii wide
                        $string3_SharpGraphView_offensive_tool_keyword = /\\SharpGraphView\.sln/ nocase ascii wide
                        $string4_SharpGraphView_offensive_tool_keyword = /\\sharpgraphview\\/ nocase ascii wide
                        $string5_SharpGraphView_offensive_tool_keyword = ">SharpGraphView<" nocase ascii wide
                        $string6_SharpGraphView_offensive_tool_keyword = "2beff60039dfd82bd092bae6e69a92ed04cdcf7cfe597868bb161dbc15c3de73" nocase ascii wide
                        $string7_SharpGraphView_offensive_tool_keyword = "3922246663d030813506516c147f8281d8c81f1cdc1153238643f580b52093d7" nocase ascii wide
                        $string8_SharpGraphView_offensive_tool_keyword = "64d0026295c3c887bbcb256967aae006f4df254a2bc9418f9a1dc30fd6115ee1" nocase ascii wide
                        $string9_SharpGraphView_offensive_tool_keyword = "825E2088-EC7C-4AB0-852A-4F1FEF178E37" nocase ascii wide
                        $string10_SharpGraphView_offensive_tool_keyword = "mlcsec/SharpGraphView" nocase ascii wide
                        $string11_SharpGraphView_offensive_tool_keyword = /SharpGraph\.exe\sGet\-UserChatMessages\s\-id\s/ nocase ascii wide
                        $string12_SharpGraphView_offensive_tool_keyword = /SharpGraph\.exe\sList\-ChatMessages\s/ nocase ascii wide
                        $string13_SharpGraphView_offensive_tool_keyword = /SharpGraphView\.exe/ nocase ascii wide
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
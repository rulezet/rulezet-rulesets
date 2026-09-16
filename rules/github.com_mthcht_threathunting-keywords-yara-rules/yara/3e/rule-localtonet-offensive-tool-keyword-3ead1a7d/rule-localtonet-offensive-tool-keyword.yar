rule rule_localtonet_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'localtonet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "localtonet"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_localtonet_offensive_tool_keyword = /\slocaltonet\.service/ nocase ascii wide
                        $string2_localtonet_offensive_tool_keyword = /\/localtonet\.dll/ nocase ascii wide
                        $string3_localtonet_offensive_tool_keyword = /\/localtonet\.exe/ nocase ascii wide
                        $string4_localtonet_offensive_tool_keyword = /\/localtonet\.git/ nocase ascii wide
                        $string5_localtonet_offensive_tool_keyword = /\/localtonet\.service/
                        $string6_localtonet_offensive_tool_keyword = "/localtonet-win" nocase ascii wide
                        $string7_localtonet_offensive_tool_keyword = "/opt/localtonet"
                        $string8_localtonet_offensive_tool_keyword = /\\localtonet\.dll/ nocase ascii wide
                        $string9_localtonet_offensive_tool_keyword = /\\localtonet\.exe/ nocase ascii wide
                        $string10_localtonet_offensive_tool_keyword = /\\localtonet\-win/ nocase ascii wide
                        $string11_localtonet_offensive_tool_keyword = "925fe97c66e61207fec6e73bf01385139ccf6a482c234cb63f1bfafa6b260cb7" nocase ascii wide
                        $string12_localtonet_offensive_tool_keyword = "a82ec4a7feac8a7bcab876286599e1df136c93ac470ba634fa77be156ee40615" nocase ascii wide
                        $string13_localtonet_offensive_tool_keyword = /\-e\slocaltonet\.service/ nocase ascii wide
                        $string14_localtonet_offensive_tool_keyword = "e27bbd5323fd6e3c1fcd501bf9279dd83fa211892c10ebf552773f4f5c89e4ab" nocase ascii wide
                        $string15_localtonet_offensive_tool_keyword = "engineseller/localtonet" nocase ascii wide
                        $string16_localtonet_offensive_tool_keyword = /localtonet\.com\/download\// nocase ascii wide
                        $string17_localtonet_offensive_tool_keyword = /queue\.localtonet\.com/ nocase ascii wide
                        $string18_localtonet_offensive_tool_keyword = /seq\.localtonet\.com\/api/ nocase ascii wide
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
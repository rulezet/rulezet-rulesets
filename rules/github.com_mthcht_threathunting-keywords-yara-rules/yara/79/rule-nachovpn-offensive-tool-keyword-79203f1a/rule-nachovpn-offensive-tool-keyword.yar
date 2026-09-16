rule rule_NachoVPN_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NachoVPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NachoVPN"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NachoVPN_offensive_tool_keyword = " localgroup administrators pwnd /add" nocase ascii wide
                        $string2_NachoVPN_offensive_tool_keyword = /\snachovpn\.server/ nocase ascii wide
                        $string3_NachoVPN_offensive_tool_keyword = " nachovpn:latest " nocase ascii wide
                        $string4_NachoVPN_offensive_tool_keyword = " --rm -it nachovpn" nocase ascii wide
                        $string5_NachoVPN_offensive_tool_keyword = " user pwnd Passw0rd123!" nocase ascii wide
                        $string6_NachoVPN_offensive_tool_keyword = /\/NachoVPN\.git/ nocase ascii wide
                        $string7_NachoVPN_offensive_tool_keyword = "/nachovpn:release" nocase ascii wide
                        $string8_NachoVPN_offensive_tool_keyword = /\/nachovpn\-1\.0\.0\-py3\-none\-any\.whl/ nocase ascii wide
                        $string9_NachoVPN_offensive_tool_keyword = "AmberWolfCyber/NachoVPN" nocase ascii wide
                        $string10_NachoVPN_offensive_tool_keyword = /connect\.nachovpn\.local/ nocase ascii wide
                        $string11_NachoVPN_offensive_tool_keyword = /nachovpn\.core\./ nocase ascii wide
                        $string12_NachoVPN_offensive_tool_keyword = /nachovpn\.local/ nocase ascii wide
                        $string13_NachoVPN_offensive_tool_keyword = /nachovpn\.plugins\./ nocase ascii wide
                        $string14_NachoVPN_offensive_tool_keyword = /nachovpn\/server\.py/ nocase ascii wide
                        $string15_NachoVPN_offensive_tool_keyword = "touch /tmp/pwnd"
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
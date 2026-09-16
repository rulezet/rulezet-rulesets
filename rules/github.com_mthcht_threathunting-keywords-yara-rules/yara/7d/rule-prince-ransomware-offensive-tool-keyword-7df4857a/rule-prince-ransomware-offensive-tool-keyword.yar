rule rule_Prince_Ransomware_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Prince-Ransomware' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Prince-Ransomware"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Prince_Ransomware_offensive_tool_keyword = "---------- Prince Ransomware ----------" nocase ascii wide
                        $string2_Prince_Ransomware_offensive_tool_keyword = /\/Prince\-Built\.exe/ nocase ascii wide
                        $string3_Prince_Ransomware_offensive_tool_keyword = /\/Prince\-Ransomware\.git/ nocase ascii wide
                        $string4_Prince_Ransomware_offensive_tool_keyword = /\\Prince\.v1\.0\.0\.zip/ nocase ascii wide
                        $string5_Prince_Ransomware_offensive_tool_keyword = /\\Prince\-Built\.exe/ nocase ascii wide
                        $string6_Prince_Ransomware_offensive_tool_keyword = "33c1c910095186228f4a1843ab48098179b8ef57d0b235cdd483da5438a4aa49" nocase ascii wide
                        $string7_Prince_Ransomware_offensive_tool_keyword = "56fa384aada24362640f70277b54bf5d91c3befaf445e5428a60cd44fba2fba1" nocase ascii wide
                        $string8_Prince_Ransomware_offensive_tool_keyword = "77227879203ee0e49d64978edc6f40c590df6e1bb6260f65340fc713880301e8" nocase ascii wide
                        $string9_Prince_Ransomware_offensive_tool_keyword = "844405c37fe6e576573b01a4384120e7837d20ee2deb849eedd9d6a966b046f4" nocase ascii wide
                        $string10_Prince_Ransomware_offensive_tool_keyword = "e7c8fc74e31020a6c52c225c143a58c1243ec86e00fcd9038b8194418f8e3603" nocase ascii wide
                        $string11_Prince_Ransomware_offensive_tool_keyword = /https\:\/\/i\.imgur\.com\/RfsCOES\.png/ nocase ascii wide
                        $string12_Prince_Ransomware_offensive_tool_keyword = "Prince-Ransomware/releases/download" nocase ascii wide
                        $string13_Prince_Ransomware_offensive_tool_keyword = "SecDbg/Prince-Ransomware" nocase ascii wide
                        $string14_Prince_Ransomware_offensive_tool_keyword = "Your files have been encrypted using Prince Ransomware!" nocase ascii wide
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
rule rule_PackMyPayload_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PackMyPayload' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PackMyPayload"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PackMyPayload_offensive_tool_keyword = " --backdoor " nocase ascii wide
                        $string2_PackMyPayload_offensive_tool_keyword = /\/PackMyPayload\.git/ nocase ascii wide
                        $string3_PackMyPayload_offensive_tool_keyword = "/PackMyPayload/" nocase ascii wide
                        $string4_PackMyPayload_offensive_tool_keyword = /\[\+\]\sBackdoored\sexisting\s7zip\swith\sspecified\sinput\sfile/ nocase ascii wide
                        $string5_PackMyPayload_offensive_tool_keyword = /\[\+\]\sBackdoored\sexisting\sISO\s/ nocase ascii wide
                        $string6_PackMyPayload_offensive_tool_keyword = /\[\+\]\sBackdoored\sexisting\sMSI\s/ nocase ascii wide
                        $string7_PackMyPayload_offensive_tool_keyword = /\[\+\]\sBackdoored\sexisting\sVHD\s/ nocase ascii wide
                        $string8_PackMyPayload_offensive_tool_keyword = /Backdooring\sMSI\sfiles\sis\scurrently\snot\ssupported\./ nocase ascii wide
                        $string9_PackMyPayload_offensive_tool_keyword = "ddde81ecf809882929faefd5887095a9d8671979f0c4d68579fa8b3a07674768" nocase ascii wide
                        $string10_PackMyPayload_offensive_tool_keyword = "File specifed to backdoor does not exist: " nocase ascii wide
                        $string11_PackMyPayload_offensive_tool_keyword = "mgeeky/PackMyPayload" nocase ascii wide
                        $string12_PackMyPayload_offensive_tool_keyword = /PackMyPayload\.py/ nocase ascii wide
                        $string13_PackMyPayload_offensive_tool_keyword = "PackMyPayload-master" nocase ascii wide
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
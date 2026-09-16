rule rule_rdpv_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rdpv' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rdpv"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_rdpv_offensive_tool_keyword = /\srdpv\.exe/ nocase ascii wide
                        $string2_rdpv_offensive_tool_keyword = /\/rdpv\.exe/ nocase ascii wide
                        $string3_rdpv_offensive_tool_keyword = /\/toolsdownload\/rdpv\.zip/ nocase ascii wide
                        $string4_rdpv_offensive_tool_keyword = /\\rdpv\.exe/ nocase ascii wide
                        $string5_rdpv_offensive_tool_keyword = ">Password Recovery for Remote Desktop<" nocase ascii wide
                        $string6_rdpv_offensive_tool_keyword = ">Remote Desktop PassView<" nocase ascii wide
                        $string7_rdpv_offensive_tool_keyword = "205818e10c13d2e51b4c0196ca30111276ca1107fc8e25a0992fe67879eab964" nocase ascii wide
                        $string8_rdpv_offensive_tool_keyword = "528de69797c36423a1e6b64fa8b1825f354e6707f2ca3760d81a9f58d69d58bb" nocase ascii wide
                        $string9_rdpv_offensive_tool_keyword = /RemoteDesktopPassView\.zip/ nocase ascii wide
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
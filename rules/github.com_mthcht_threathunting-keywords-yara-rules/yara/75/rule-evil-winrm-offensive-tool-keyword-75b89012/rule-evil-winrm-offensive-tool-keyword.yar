rule rule_evil_winrm_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'evil-winrm' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "evil-winrm"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_evil_winrm_offensive_tool_keyword = /\sdownload\s.{0,100}\\NTDS\\NTDS\.dit/ nocase ascii wide
                        $string2_evil_winrm_offensive_tool_keyword = /\sdownload\s.{0,100}\\Windows\\System32\\config\\SYSTEM/ nocase ascii wide
                        $string3_evil_winrm_offensive_tool_keyword = "Bypass-4MSI" nocase ascii wide
                        $string4_evil_winrm_offensive_tool_keyword = /cmd\s\/c\smklink\s\/d\s.{0,100}\sHarddiskVolumeShadowCopy1/ nocase ascii wide
                        $string5_evil_winrm_offensive_tool_keyword = "Dll-Loader -http -path " nocase ascii wide
                        $string6_evil_winrm_offensive_tool_keyword = "Dll-Loader -local -path" nocase ascii wide
                        $string7_evil_winrm_offensive_tool_keyword = "Dll-Loader -smb -path " nocase ascii wide
                        $string8_evil_winrm_offensive_tool_keyword = "Donut-Loader -process_id" nocase ascii wide
                        $string9_evil_winrm_offensive_tool_keyword = /donut\-maker\.py\s\-i\s.{0,100}\.exe/ nocase ascii wide
                        $string10_evil_winrm_offensive_tool_keyword = /download\s.{0,100}Roaming\\mRemoteNG\\confCons\.xml/ nocase ascii wide
                        $string11_evil_winrm_offensive_tool_keyword = "evil-winrm" nocase ascii wide
                        $string12_evil_winrm_offensive_tool_keyword = /Invoke\-Binary\s.{0,100}\.exe/ nocase ascii wide
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
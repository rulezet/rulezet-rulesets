rule rule_SharpSQL_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpSQL' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSQL"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpSQL_offensive_tool_keyword = /\.exe\sEnable\-LinkedCmdshell/ nocase ascii wide
                        $string2_SharpSQL_offensive_tool_keyword = /\.exe\sGet\-Hash\s\-Instance\s.{0,100}\s\-ip\s/ nocase ascii wide
                        $string3_SharpSQL_offensive_tool_keyword = /\.exe\sGet\-LinkedServers\s\-Instance\s/ nocase ascii wide
                        $string4_SharpSQL_offensive_tool_keyword = /\.exe\sGet\-SQLInstanceDomain/ nocase ascii wide
                        $string5_SharpSQL_offensive_tool_keyword = /\.exe\sGet\-Sysadmins\s\-Instance\s/ nocase ascii wide
                        $string6_SharpSQL_offensive_tool_keyword = /\.exe\sGet\-UserPrivs\s\-Instance\s/ nocase ascii wide
                        $string7_SharpSQL_offensive_tool_keyword = /\.exe\sInvoke\-CLRAsm\s\-Instance\s.{0,100}\s\-Command\s/ nocase ascii wide
                        $string8_SharpSQL_offensive_tool_keyword = /\.exe\sInvoke\-LinkedOSCmd\s\-Instance\s/ nocase ascii wide
                        $string9_SharpSQL_offensive_tool_keyword = /\.exe\sInvoke\-OLEObject\s/ nocase ascii wide
                        $string10_SharpSQL_offensive_tool_keyword = /\.exe\sInvoke\-OSCmd\s\-Instance\s.{0,100}\s\-Command\s/ nocase ascii wide
                        $string11_SharpSQL_offensive_tool_keyword = /\.exe\sInvoke\-UserImpersonation\s/ nocase ascii wide
                        $string12_SharpSQL_offensive_tool_keyword = /\/SharpSQL\.exe/ nocase ascii wide
                        $string13_SharpSQL_offensive_tool_keyword = /\\SharpSQL\.exe/ nocase ascii wide
                        $string14_SharpSQL_offensive_tool_keyword = /\\SharpSQL\.pdb/ nocase ascii wide
                        $string15_SharpSQL_offensive_tool_keyword = ">SharpSQL<" nocase ascii wide
                        $string16_SharpSQL_offensive_tool_keyword = "SharpSQL by @mlcsec" nocase ascii wide
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
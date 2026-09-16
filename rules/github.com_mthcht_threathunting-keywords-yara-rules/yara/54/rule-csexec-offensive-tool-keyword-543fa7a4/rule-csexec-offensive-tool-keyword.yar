rule rule_csexec_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'csexec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "csexec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_csexec_offensive_tool_keyword = /\/csexec\.exe/ nocase ascii wide
                        $string2_csexec_offensive_tool_keyword = /\/CSExec\.git/ nocase ascii wide
                        $string3_csexec_offensive_tool_keyword = /\/csexecsvc\.exe/ nocase ascii wide
                        $string4_csexec_offensive_tool_keyword = /\/csexecsvc\-net35\.exe/ nocase ascii wide
                        $string5_csexec_offensive_tool_keyword = /\/csexecsvc\-net40\.exe/ nocase ascii wide
                        $string6_csexec_offensive_tool_keyword = /\/csexecsvc\-net45\.exe/ nocase ascii wide
                        $string7_csexec_offensive_tool_keyword = /\\\\.{0,100}\\pipe\\psexecsvc/ nocase ascii wide
                        $string8_csexec_offensive_tool_keyword = /\\csexec\.exe/ nocase ascii wide
                        $string9_csexec_offensive_tool_keyword = /\\csexecsvc\.exe/ nocase ascii wide
                        $string10_csexec_offensive_tool_keyword = /\\csexecsvc\-net35\.exe/ nocase ascii wide
                        $string11_csexec_offensive_tool_keyword = /\\csexecsvc\-net40\.exe/ nocase ascii wide
                        $string12_csexec_offensive_tool_keyword = /\\csexecsvc\-net45\.exe/ nocase ascii wide
                        $string13_csexec_offensive_tool_keyword = ">csexec<" nocase ascii wide
                        $string14_csexec_offensive_tool_keyword = ">csexecsvc<" nocase ascii wide
                        $string15_csexec_offensive_tool_keyword = "41A90A6A-F9ED-4A2F-8448-D544EC1FD753" nocase ascii wide
                        $string16_csexec_offensive_tool_keyword = "41A90A6A-F9ED-4A2F-8448-D544EC1FD754" nocase ascii wide
                        $string17_csexec_offensive_tool_keyword = "41A90A6A-F9ED-4A2F-8448-D544EC1FD755" nocase ascii wide
                        $string18_csexec_offensive_tool_keyword = "58ae9b923139f8bed83bed67aae0bf2e56bfec9901009e61c4e4b6b375050bec" nocase ascii wide
                        $string19_csexec_offensive_tool_keyword = "64fc0afc72a37b1071482e9c4725cd35fa2b974c6903cd01124ed7fe9d2c8e27" nocase ascii wide
                        $string20_csexec_offensive_tool_keyword = "6d11a3d59602508d435fc3cabba737d7b5d710e2b56b7623e903e59ac3d3f287" nocase ascii wide
                        $string21_csexec_offensive_tool_keyword = "73fb2d477ece754ce6ad9239126b69f9dc3dfc95775ef0714a4df26ee7ac4352" nocase ascii wide
                        $string22_csexec_offensive_tool_keyword = "F3037587-1A3B-41F1-AA71-B026EFDB2A35" nocase ascii wide
                        $string23_csexec_offensive_tool_keyword = "F3037587-1A3B-41F1-AA71-B026EFDB2A40" nocase ascii wide
                        $string24_csexec_offensive_tool_keyword = "F3037587-1A3B-41F1-AA71-B026EFDB2A45" nocase ascii wide
                        $string25_csexec_offensive_tool_keyword = "malcomvetter/CSExec" nocase ascii wide
                        $string26_csexec_offensive_tool_keyword = /This\sis\ssimilar\sto\spsexec\s\-s\s\\/ nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
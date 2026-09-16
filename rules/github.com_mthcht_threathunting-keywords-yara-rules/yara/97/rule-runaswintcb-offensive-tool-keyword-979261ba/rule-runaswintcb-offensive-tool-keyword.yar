rule rule_RunAsWinTcb_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RunAsWinTcb' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RunAsWinTcb"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RunAsWinTcb_offensive_tool_keyword = /\/dllexploit\.cpp/ nocase ascii wide
                        $string2_RunAsWinTcb_offensive_tool_keyword = /\/dllexploit\.exe/ nocase ascii wide
                        $string3_RunAsWinTcb_offensive_tool_keyword = /\/POC_DLL\.vcxproj/ nocase ascii wide
                        $string4_RunAsWinTcb_offensive_tool_keyword = /\/RunAsWinTcb\.git/ nocase ascii wide
                        $string5_RunAsWinTcb_offensive_tool_keyword = /\/RunAsWinTcb\.iml/ nocase ascii wide
                        $string6_RunAsWinTcb_offensive_tool_keyword = /\\dllexploit\.cpp/ nocase ascii wide
                        $string7_RunAsWinTcb_offensive_tool_keyword = /\\dllexploit\.exe/ nocase ascii wide
                        $string8_RunAsWinTcb_offensive_tool_keyword = /\\POC_DLL\.dll/ nocase ascii wide
                        $string9_RunAsWinTcb_offensive_tool_keyword = /\\POC_DLL\.vcxproj/ nocase ascii wide
                        $string10_RunAsWinTcb_offensive_tool_keyword = /\\RunAsWinTcb\\/ nocase ascii wide
                        $string11_RunAsWinTcb_offensive_tool_keyword = "33BF8AA2-18DE-4ED9-9613-A4118CBFC32A" nocase ascii wide
                        $string12_RunAsWinTcb_offensive_tool_keyword = "cb291da763f1ac7b8221be536e9d110a4c937c749da51b15151975c1b84f8b6d" nocase ascii wide
                        $string13_RunAsWinTcb_offensive_tool_keyword = /Choosing\sDLL\sto\shijack\./ nocase ascii wide
                        $string14_RunAsWinTcb_offensive_tool_keyword = /RunAsWinTcb\.exe/ nocase ascii wide
                        $string15_RunAsWinTcb_offensive_tool_keyword = "RunAsWinTcb-master" nocase ascii wide
                        $string16_RunAsWinTcb_offensive_tool_keyword = "tastypepperoni/RunAsWinTcb" nocase ascii wide
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
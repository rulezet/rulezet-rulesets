rule rule_ysoserial_net_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ysoserial.net' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ysoserial.net"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ysoserial_net_offensive_tool_keyword = /\s\-c\s.{0,100}ExploitClass\.cs.{0,100}System\.dll/ nocase ascii wide
                        $string2_ysoserial_net_offensive_tool_keyword = /\s\-\-cve\=.{0,100}\s\-\-command/ nocase ascii wide
                        $string3_ysoserial_net_offensive_tool_keyword = " -g ActivitySurrogateSelector" nocase ascii wide
                        $string4_ysoserial_net_offensive_tool_keyword = " -g ClaimsPrincipal " nocase ascii wide
                        $string5_ysoserial_net_offensive_tool_keyword = " -g PSObject " nocase ascii wide
                        $string6_ysoserial_net_offensive_tool_keyword = " -g TextFormattingRunProperties " nocase ascii wide
                        $string7_ysoserial_net_offensive_tool_keyword = " --gadget ActivitySurrogateSelector" nocase ascii wide
                        $string8_ysoserial_net_offensive_tool_keyword = " --gadget ClaimsPrincipal " nocase ascii wide
                        $string9_ysoserial_net_offensive_tool_keyword = " --gadget PSObject " nocase ascii wide
                        $string10_ysoserial_net_offensive_tool_keyword = /\s\-m\srun_command\s\-c\s.{0,100}\.exe/ nocase ascii wide
                        $string11_ysoserial_net_offensive_tool_keyword = " -p ActivatorUrl" nocase ascii wide
                        $string12_ysoserial_net_offensive_tool_keyword = " -p Altserialization" nocase ascii wide
                        $string13_ysoserial_net_offensive_tool_keyword = " -p DotNetNuke" nocase ascii wide
                        $string14_ysoserial_net_offensive_tool_keyword = " -p SessionSecurityTokenHandler" nocase ascii wide
                        $string15_ysoserial_net_offensive_tool_keyword = " -p TransactionManagerReenlist" nocase ascii wide
                        $string16_ysoserial_net_offensive_tool_keyword = /\/ghostfile\.aspx/ nocase ascii wide
                        $string17_ysoserial_net_offensive_tool_keyword = "/ysoserial/" nocase ascii wide
                        $string18_ysoserial_net_offensive_tool_keyword = /\\windows\\temp\\ncat\.exe\s\-nv\s/ nocase ascii wide
                        $string19_ysoserial_net_offensive_tool_keyword = /\\ysoserial\\/ nocase ascii wide
                        $string20_ysoserial_net_offensive_tool_keyword = /echo\s123\s\>\sc\:\\windows\\temp\\test\.txt/ nocase ascii wide
                        $string21_ysoserial_net_offensive_tool_keyword = "-f BinaryFormatter -g PSObject -o base64 -c " nocase ascii wide
                        $string22_ysoserial_net_offensive_tool_keyword = /\-f\sJson\.Net\s\-g\sObjectDataProvider\s\-o\sraw\s\-c\s/ nocase ascii wide
                        $string23_ysoserial_net_offensive_tool_keyword = "fakepath31337" nocase ascii wide
                        $string24_ysoserial_net_offensive_tool_keyword = /GhostWebShell\.cs/ nocase ascii wide
                        $string25_ysoserial_net_offensive_tool_keyword = /MessageBox\.Show.{0,100}Pwned/ nocase ascii wide
                        $string26_ysoserial_net_offensive_tool_keyword = /ModifiedVulnerableBinaryFormatters\\info\.txt/ nocase ascii wide
                        $string27_ysoserial_net_offensive_tool_keyword = "PCVAIExhbmd1YWdlPSJDIyIlPgpUaGlzIGlzIHRoZSBhdHRhY2tlcidzIGZpbGUgPGJyLz4KUnVubmluZyBvbiB0aGUgc2VydmVyIGlmIGA8JT0xMzM4LTElPmAgaXMgMTMzNy4" nocase ascii wide
                        $string28_ysoserial_net_offensive_tool_keyword = "TestConsoleApp_YSONET" nocase ascii wide
                        $string29_ysoserial_net_offensive_tool_keyword = "X-YSOSERIAL-NET" nocase ascii wide
                        $string30_ysoserial_net_offensive_tool_keyword = "ysoserial -" nocase ascii wide
                        $string31_ysoserial_net_offensive_tool_keyword = /ysoserial\-.{0,100}\.zip/ nocase ascii wide
                        $string32_ysoserial_net_offensive_tool_keyword = /ysoserial\.exe/ nocase ascii wide
                        $string33_ysoserial_net_offensive_tool_keyword = /ysoserial\.net/ nocase ascii wide
                        $string34_ysoserial_net_offensive_tool_keyword = /ysoserial\.sln/ nocase ascii wide
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
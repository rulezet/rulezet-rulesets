rule rule_MetasploitCoop_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MetasploitCoop' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MetasploitCoop"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MetasploitCoop_offensive_tool_keyword = " MetasploitCoop" nocase ascii wide
                        $string2_MetasploitCoop_offensive_tool_keyword = /\smsfws\.py\s/ nocase ascii wide
                        $string3_MetasploitCoop_offensive_tool_keyword = "/metasploit-coop:" nocase ascii wide
                        $string4_MetasploitCoop_offensive_tool_keyword = /\/MetasploitCoop_0x727\.git/ nocase ascii wide
                        $string5_MetasploitCoop_offensive_tool_keyword = /\/MetasploitCoop\-Backend\.git/ nocase ascii wide
                        $string6_MetasploitCoop_offensive_tool_keyword = /\/MetasploitCoop\-Frontend\.git/ nocase ascii wide
                        $string7_MetasploitCoop_offensive_tool_keyword = "/metasploit-framework/" nocase ascii wide
                        $string8_MetasploitCoop_offensive_tool_keyword = /\/msfws\.py/ nocase ascii wide
                        $string9_MetasploitCoop_offensive_tool_keyword = "/pymetasploit/"
                        $string10_MetasploitCoop_offensive_tool_keyword = /\[MetasploitCoop\-Backend\]/ nocase ascii wide
                        $string11_MetasploitCoop_offensive_tool_keyword = /\[MetasploitCoop\-Frontend\]/ nocase ascii wide
                        $string12_MetasploitCoop_offensive_tool_keyword = /\\\\system32\\\\msf\.sys/ nocase ascii wide
                        $string13_MetasploitCoop_offensive_tool_keyword = /\\system32\\msf\.sys/ nocase ascii wide
                        $string14_MetasploitCoop_offensive_tool_keyword = "0x727/MetasploitCoop_0x727" nocase ascii wide
                        $string15_MetasploitCoop_offensive_tool_keyword = "0x727/MetasploitCoop-Backend" nocase ascii wide
                        $string16_MetasploitCoop_offensive_tool_keyword = "0x727/MetasploitCoop-Frontend" nocase ascii wide
                        $string17_MetasploitCoop_offensive_tool_keyword = "877d4290b0f991fcf2fb3e5f64916a2dfb844280010df806d28a94ad57f0de07" nocase ascii wide
                        $string18_MetasploitCoop_offensive_tool_keyword = "8915669ca2e25c835fbc5c022b3f1d62fab4569190e216a4b37a8d1e4f94208c" nocase ascii wide
                        $string19_MetasploitCoop_offensive_tool_keyword = "CREATE DATABASE homados" nocase ascii wide
                        $string20_MetasploitCoop_offensive_tool_keyword = /https\:\/\/127\.0\.0\.1\:60443/ nocase ascii wide
                        $string21_MetasploitCoop_offensive_tool_keyword = "killme:qAuxiAwegDsZI" nocase ascii wide
                        $string22_MetasploitCoop_offensive_tool_keyword = /MIIEpAIBAAKCAQEAp4fWROz5dd1ylzYsMWYY6Y\+EBfPjvieE7EniddfMkA7ss47F/ nocase ascii wide
                        $string23_MetasploitCoop_offensive_tool_keyword = "MSF_WS_JSON_RPC_API_TOKEN" nocase ascii wide
                        $string24_MetasploitCoop_offensive_tool_keyword = /payload\/pezor\.py/ nocase ascii wide
                        $string25_MetasploitCoop_offensive_tool_keyword = "payload/windows/dllinject/bind_tcp_uuid" nocase ascii wide
                        $string26_MetasploitCoop_offensive_tool_keyword = "Starting Browser Autopwn with Adobe Flash-only BrowserExploitServer-based exploits" nocase ascii wide
                        $string27_MetasploitCoop_offensive_tool_keyword = "starting the post exploitation with post exploitation modules" nocase ascii wide
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
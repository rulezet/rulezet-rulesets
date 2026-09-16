rule MetasploitCoop
{
    meta:
        description = "Detection patterns for the tool 'MetasploitCoop' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MetasploitCoop"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " MetasploitCoop" nocase ascii wide
                        $string2 = /\smsfws\.py\s/ nocase ascii wide
                        $string3 = "/metasploit-coop:" nocase ascii wide
                        $string4 = /\/MetasploitCoop_0x727\.git/ nocase ascii wide
                        $string5 = /\/MetasploitCoop\-Backend\.git/ nocase ascii wide
                        $string6 = /\/MetasploitCoop\-Frontend\.git/ nocase ascii wide
                        $string7 = "/metasploit-framework/" nocase ascii wide
                        $string8 = /\/msfws\.py/ nocase ascii wide
                        $string9 = "/pymetasploit/"
                        $string10 = /\[MetasploitCoop\-Backend\]/ nocase ascii wide
                        $string11 = /\[MetasploitCoop\-Frontend\]/ nocase ascii wide
                        $string12 = /\\\\system32\\\\msf\.sys/ nocase ascii wide
                        $string13 = /\\system32\\msf\.sys/ nocase ascii wide
                        $string14 = "0x727/MetasploitCoop_0x727" nocase ascii wide
                        $string15 = "0x727/MetasploitCoop-Backend" nocase ascii wide
                        $string16 = "0x727/MetasploitCoop-Frontend" nocase ascii wide
                        $string17 = "877d4290b0f991fcf2fb3e5f64916a2dfb844280010df806d28a94ad57f0de07" nocase ascii wide
                        $string18 = "8915669ca2e25c835fbc5c022b3f1d62fab4569190e216a4b37a8d1e4f94208c" nocase ascii wide
                        $string19 = "CREATE DATABASE homados" nocase ascii wide
                        $string20 = /https\:\/\/127\.0\.0\.1\:60443/ nocase ascii wide
                        $string21 = "killme:qAuxiAwegDsZI" nocase ascii wide
                        $string22 = /MIIEpAIBAAKCAQEAp4fWROz5dd1ylzYsMWYY6Y\+EBfPjvieE7EniddfMkA7ss47F/ nocase ascii wide
                        $string23 = "MSF_WS_JSON_RPC_API_TOKEN" nocase ascii wide
                        $string24 = /payload\/pezor\.py/ nocase ascii wide
                        $string25 = "payload/windows/dllinject/bind_tcp_uuid" nocase ascii wide
                        $string26 = "Starting Browser Autopwn with Adobe Flash-only BrowserExploitServer-based exploits" nocase ascii wide
                        $string27 = "starting the post exploitation with post exploitation modules" nocase ascii wide

    condition:
        any of them
}
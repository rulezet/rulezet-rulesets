rule ysoserial_net
{
    meta:
        description = "Detection patterns for the tool 'ysoserial.net' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ysoserial.net"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-c\s.{0,1000}ExploitClass\.cs.{0,1000}System\.dll/ nocase ascii wide
                        $string2 = /\s\-\-cve\=.{0,1000}\s\-\-command/ nocase ascii wide
                        $string3 = " -g ActivitySurrogateSelector" nocase ascii wide
                        $string4 = " -g ClaimsPrincipal " nocase ascii wide
                        $string5 = " -g PSObject " nocase ascii wide
                        $string6 = " -g TextFormattingRunProperties " nocase ascii wide
                        $string7 = " --gadget ActivitySurrogateSelector" nocase ascii wide
                        $string8 = " --gadget ClaimsPrincipal " nocase ascii wide
                        $string9 = " --gadget PSObject " nocase ascii wide
                        $string10 = /\s\-m\srun_command\s\-c\s.{0,1000}\.exe/ nocase ascii wide
                        $string11 = " -p ActivatorUrl" nocase ascii wide
                        $string12 = " -p Altserialization" nocase ascii wide
                        $string13 = " -p DotNetNuke" nocase ascii wide
                        $string14 = " -p SessionSecurityTokenHandler" nocase ascii wide
                        $string15 = " -p TransactionManagerReenlist" nocase ascii wide
                        $string16 = /\/ghostfile\.aspx/ nocase ascii wide
                        $string17 = "/ysoserial/" nocase ascii wide
                        $string18 = /\\windows\\temp\\ncat\.exe\s\-nv\s/ nocase ascii wide
                        $string19 = /\\ysoserial\\/ nocase ascii wide
                        $string20 = /echo\s123\s\>\sc\:\\windows\\temp\\test\.txt/ nocase ascii wide
                        $string21 = "-f BinaryFormatter -g PSObject -o base64 -c " nocase ascii wide
                        $string22 = /\-f\sJson\.Net\s\-g\sObjectDataProvider\s\-o\sraw\s\-c\s/ nocase ascii wide
                        $string23 = "fakepath31337" nocase ascii wide
                        $string24 = /GhostWebShell\.cs/ nocase ascii wide
                        $string25 = /MessageBox\.Show.{0,1000}Pwned/ nocase ascii wide
                        $string26 = /ModifiedVulnerableBinaryFormatters\\info\.txt/ nocase ascii wide
                        $string27 = "PCVAIExhbmd1YWdlPSJDIyIlPgpUaGlzIGlzIHRoZSBhdHRhY2tlcidzIGZpbGUgPGJyLz4KUnVubmluZyBvbiB0aGUgc2VydmVyIGlmIGA8JT0xMzM4LTElPmAgaXMgMTMzNy4" nocase ascii wide
                        $string28 = "TestConsoleApp_YSONET" nocase ascii wide
                        $string29 = "X-YSOSERIAL-NET" nocase ascii wide
                        $string30 = "ysoserial -" nocase ascii wide
                        $string31 = /ysoserial\-.{0,1000}\.zip/ nocase ascii wide
                        $string32 = /ysoserial\.exe/ nocase ascii wide
                        $string33 = /ysoserial\.net/ nocase ascii wide
                        $string34 = /ysoserial\.sln/ nocase ascii wide

    condition:
        any of them
}
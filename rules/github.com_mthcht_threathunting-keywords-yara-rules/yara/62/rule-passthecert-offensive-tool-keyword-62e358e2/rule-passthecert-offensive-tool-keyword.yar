rule rule_PassTheCert_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PassTheCert' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PassTheCert"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PassTheCert_offensive_tool_keyword = " -just-dc-ntlm -just-dc-user krbtgt " nocase ascii wide
                        $string2_PassTheCert_offensive_tool_keyword = /\s\-\-server\s.{0,1000}\s\-\-cert\-path\s.{0,1000}\.pfx\s\-\-elevate\s\-\-target\s.{0,1000}\s\-\-restore\s/ nocase ascii wide
                        $string3_PassTheCert_offensive_tool_keyword = /\s\-\-server\s.{0,1000}\s\-\-cert\-path\s.{0,1000}\.pfx\s\-\-elevate\s\-\-target\s.{0,1000}\s\-\-sid\s/ nocase ascii wide
                        $string4_PassTheCert_offensive_tool_keyword = /\swmiexec\.py\s\-k\s\-no\-pass\s/ nocase ascii wide
                        $string5_PassTheCert_offensive_tool_keyword = /\\"Granted\suser\s.{0,1000}\sDCSYNC\srights\!/ nocase ascii wide
                        $string6_PassTheCert_offensive_tool_keyword = /\.py\s\-action\sadd_computer\s\-crt\s.{0,1000}\s\-key\s.{0,1000}\s\-domain\s.{0,1000}\s\-dc\-ip\s.{0,1000}\s\-computer\-name\s.{0,1000}\s\-computer\-pass\s/ nocase ascii wide
                        $string7_PassTheCert_offensive_tool_keyword = /\/PassTheCert\.exe/ nocase ascii wide
                        $string8_PassTheCert_offensive_tool_keyword = /\/PassTheCert\.git/ nocase ascii wide
                        $string9_PassTheCert_offensive_tool_keyword = /\\PassTheCert\.cs/ nocase ascii wide
                        $string10_PassTheCert_offensive_tool_keyword = /\\PassTheCert\.exe/ nocase ascii wide
                        $string11_PassTheCert_offensive_tool_keyword = /\\PassTheCert\.pdb/ nocase ascii wide
                        $string12_PassTheCert_offensive_tool_keyword = /\\PassTheCert\.sln/ nocase ascii wide
                        $string13_PassTheCert_offensive_tool_keyword = ">PassTheCert<" nocase ascii wide
                        $string14_PassTheCert_offensive_tool_keyword = "51f92adcb4397e57d3809d3fa76bbf2cfb8ca772551b755ea8b0b3a6ba316334" nocase ascii wide
                        $string15_PassTheCert_offensive_tool_keyword = "AlmondOffSec/PassTheCert" nocase ascii wide
                        $string16_PassTheCert_offensive_tool_keyword = "b0c674b496620842bae84b3e11231c4913ba57e9c4aa9458e670c153a66be810" nocase ascii wide
                        $string17_PassTheCert_offensive_tool_keyword = "BBCD0202-C086-437C-A606-015456F90C46" nocase ascii wide
                        $string18_PassTheCert_offensive_tool_keyword = /can\snow\simpersonate\susers\son\s.{0,1000}\svia\sS4U2Proxy/ nocase ascii wide
                        $string19_PassTheCert_offensive_tool_keyword = /getST\.py\s\-spn\s/ nocase ascii wide
                        $string20_PassTheCert_offensive_tool_keyword = /PassTheCert\.csproj/ nocase ascii wide
                        $string21_PassTheCert_offensive_tool_keyword = /PassTheCert\.exe/ nocase ascii wide
                        $string22_PassTheCert_offensive_tool_keyword = /passthecert\.py/ nocase ascii wide
                        $string23_PassTheCert_offensive_tool_keyword = /secretsdump\.py/ nocase ascii wide

    condition:
        any of them
}
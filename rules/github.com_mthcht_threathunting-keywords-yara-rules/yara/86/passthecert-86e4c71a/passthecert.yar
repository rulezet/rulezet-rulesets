rule PassTheCert
{
    meta:
        description = "Detection patterns for the tool 'PassTheCert' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PassTheCert"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -just-dc-ntlm -just-dc-user krbtgt " nocase ascii wide
                        $string2 = /\s\-\-server\s.{0,1000}\s\-\-cert\-path\s.{0,1000}\.pfx\s\-\-elevate\s\-\-target\s.{0,1000}\s\-\-restore\s/ nocase ascii wide
                        $string3 = /\s\-\-server\s.{0,1000}\s\-\-cert\-path\s.{0,1000}\.pfx\s\-\-elevate\s\-\-target\s.{0,1000}\s\-\-sid\s/ nocase ascii wide
                        $string4 = /\swmiexec\.py\s\-k\s\-no\-pass\s/ nocase ascii wide
                        $string5 = /\\"Granted\suser\s.{0,1000}\sDCSYNC\srights\!/ nocase ascii wide
                        $string6 = /\.py\s\-action\sadd_computer\s\-crt\s.{0,1000}\s\-key\s.{0,1000}\s\-domain\s.{0,1000}\s\-dc\-ip\s.{0,1000}\s\-computer\-name\s.{0,1000}\s\-computer\-pass\s/ nocase ascii wide
                        $string7 = /\/PassTheCert\.exe/ nocase ascii wide
                        $string8 = /\/PassTheCert\.git/ nocase ascii wide
                        $string9 = /\\PassTheCert\.cs/ nocase ascii wide
                        $string10 = /\\PassTheCert\.exe/ nocase ascii wide
                        $string11 = /\\PassTheCert\.pdb/ nocase ascii wide
                        $string12 = /\\PassTheCert\.sln/ nocase ascii wide
                        $string13 = ">PassTheCert<" nocase ascii wide
                        $string14 = "51f92adcb4397e57d3809d3fa76bbf2cfb8ca772551b755ea8b0b3a6ba316334" nocase ascii wide
                        $string15 = "AlmondOffSec/PassTheCert" nocase ascii wide
                        $string16 = "b0c674b496620842bae84b3e11231c4913ba57e9c4aa9458e670c153a66be810" nocase ascii wide
                        $string17 = "BBCD0202-C086-437C-A606-015456F90C46" nocase ascii wide
                        $string18 = /can\snow\simpersonate\susers\son\s.{0,1000}\svia\sS4U2Proxy/ nocase ascii wide
                        $string19 = /getST\.py\s\-spn\s/ nocase ascii wide
                        $string20 = /PassTheCert\.csproj/ nocase ascii wide
                        $string21 = /PassTheCert\.exe/ nocase ascii wide
                        $string22 = /passthecert\.py/ nocase ascii wide
                        $string23 = /secretsdump\.py/ nocase ascii wide

    condition:
        any of them
}
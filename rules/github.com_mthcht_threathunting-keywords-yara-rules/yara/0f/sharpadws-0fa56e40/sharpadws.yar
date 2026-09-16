rule SharpADWS
{
    meta:
        description = "Detection patterns for the tool 'SharpADWS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpADWS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\scan\snow\simpersonate\susers\son\s.{0,1000}\svia\sS4U2Proxy/ nocase ascii wide
                        $string2 = " Kerberoastable -action list" nocase ascii wide
                        $string3 = " Kerberoastable -action write -target " nocase ascii wide
                        $string4 = /\sRBCD\s\-action\swrite\s\-delegate\-to\s.{0,1000}\s\-delegate\-from\s/ nocase ascii wide
                        $string5 = /\.exe\sacl\s\-dn\s.{0,1000}\s\-scope\s.{0,1000}\s\-trustee\s/ nocase ascii wide
                        $string6 = /\.exe\sCertify\s\-action\sfind\s\-enrolleeSuppliesSubject\s\-clientAuth/ nocase ascii wide
                        $string7 = /\.exe\sCertify\s\-action\sfind/ nocase ascii wide
                        $string8 = /\.exe\sDCSync\s\-action\slist/ nocase ascii wide
                        $string9 = /\.exe\sDCSync\s\-action\swrite\s\-target\s/ nocase ascii wide
                        $string10 = /\.exe\sDontReqPreAuth\s\-action\slist/ nocase ascii wide
                        $string11 = /\.exe\sDontReqPreAuth\s\-action\swrite\s\-target\s/ nocase ascii wide
                        $string12 = /\.exe\sRBCD\s\-action\sread\s\-delegate\-to\s/ nocase ascii wide
                        $string13 = /\.exe\sWhisker\s\-action\sadd\s\-target\s.{0,1000}\s\-cert\-pass\s/ nocase ascii wide
                        $string14 = /\.exe\sWhisker\s\-action\slist\s\-target\s/ nocase ascii wide
                        $string15 = /\/SharpADWS\.git/ nocase ascii wide
                        $string16 = /\[\-\]\sAccount\sto\skerberoast\sdoes\snot\sexist\!/ nocase ascii wide
                        $string17 = /\[\-\]\sElevating\s.{0,1000}\swith\sDCSync\sprivileges\sfailed/ nocase ascii wide
                        $string18 = /\\SharpADWS\.csproj/ nocase ascii wide
                        $string19 = /\\SharpADWS\.sln/ nocase ascii wide
                        $string20 = /\\SharpADWS\\/ nocase ascii wide
                        $string21 = /\\SharpADWS\-master/ nocase ascii wide
                        $string22 = /\]\sFound\skerberoastable\susers\:\s/ nocase ascii wide
                        $string23 = /\]\sKerberoast\suser\s.{0,1000}\ssuccessfully\!/ nocase ascii wide
                        $string24 = "70ef0d3588b87bd71c2774c1bb177f59ae31a99b1a4ef82f7d2a16175c3caaf6" nocase ascii wide
                        $string25 = "AA488748-3D0E-4A52-8747-AB42A7143760" nocase ascii wide
                        $string26 = /SharpADWS\s1\.0\.0\-beta\s\-\sCopyright/ nocase ascii wide
                        $string27 = /SharpADWS\.exe/ nocase ascii wide
                        $string28 = "wh0amitz/SharpADWS" nocase ascii wide

    condition:
        any of them
}
rule Xrulez
{
    meta:
        description = "Detection patterns for the tool 'Xrulez' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Xrulez"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sXRulez\.cpp/ nocase ascii wide
                        $string2 = /\/XRulez\sbinaries\.zip/ nocase ascii wide
                        $string3 = /\/XRulez\.exe/ nocase ascii wide
                        $string4 = /\/XRulez\.zip/ nocase ascii wide
                        $string5 = /\\2fac5c2a114c7896c33fb2b0a9f6443d\\/ nocase ascii wide
                        $string6 = /\\XRulez\.cpp/ nocase ascii wide
                        $string7 = /\\XRulez\.exe/ nocase ascii wide
                        $string8 = /\\XRulez\.sln/ nocase ascii wide
                        $string9 = /\\XRulez\.zip/ nocase ascii wide
                        $string10 = /\\XRulez\\Injector\\/ nocase ascii wide
                        $string11 = "070ccb075d1dada74121d232e657a9aeda429014f44da57491aa92fc5a279924" nocase ascii wide
                        $string12 = "14083A04-DD4B-4E7D-A16E-86947D3D6D74" nocase ascii wide
                        $string13 = "2661F29C-69F5-4010-9198-A418C061DD7C" nocase ascii wide
                        $string14 = "578a42cf90cf1bcc569f925d7909bbedd2756367906d2875a23cbc8bb1628577" nocase ascii wide
                        $string15 = "b90d7a75d6c85314b6232306f73ee17783f5b00882f264381ad3a9f4c2bedfa7" nocase ascii wide
                        $string16 = "b90d7a75d6c85314b6232306f73ee17783f5b00882f264381ad3a9f4c2bedfa7" nocase ascii wide
                        $string17 = /XRMod_h64e\.exe/ nocase ascii wide
                        $string18 = /Xrulez\s\+\sXRMod\.rwdi\.binaries\.zip/ nocase ascii wide
                        $string19 = /Xrulez\s\+\sXRMod\.x64\.binaries\.zip/ nocase ascii wide
                        $string20 = /Xrulez\s\+\sXRMod\.x86\.binaries\.zip/ nocase ascii wide
                        $string21 = /XRulez\sbinaries\.zip/ nocase ascii wide
                        $string22 = /XRulez\.\%2B\.XRMod\.rwdi\.binaries\.zip/ nocase ascii wide
                        $string23 = /XRulez\.\%2B\.XRMod\.x64\.binaries\.zip/ nocase ascii wide
                        $string24 = /XRulez\.\%2B\.XRMod\.x86\.binaries\.zip/ nocase ascii wide
                        $string25 = /XRulez\.\+\.XRMod\.x64\.binaries/ nocase ascii wide
                        $string26 = /XRulez\.exe\s/ nocase ascii wide
                        $string27 = /XRulez_h64d\.dll/ nocase ascii wide
                        $string28 = /XRulez_h64e\.exe/ nocase ascii wide
                        $string29 = /XRulez_rwdi86d\.dll/ nocase ascii wide
                        $string30 = /XRulezDll_rwdi64\.dll/ nocase ascii wide

    condition:
        any of them
}
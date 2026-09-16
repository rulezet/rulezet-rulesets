rule ShadowSpray
{
    meta:
        description = "Detection patterns for the tool 'ShadowSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShadowSpray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " - ShadowSpray" nocase ascii wide
                        $string2 = " --RestoreShadowCred" nocase ascii wide
                        $string3 = /\/ShadowSpray\.git/ nocase ascii wide
                        $string4 = /\/ShadowSpray\.git/ nocase ascii wide
                        $string5 = /\/ShadowSpray\/.{0,1000}\.cs/ nocase ascii wide
                        $string6 = /\[\!\]\sUnhandled\sShadowSpray\.Kerb\sexception\:/ nocase ascii wide
                        $string7 = /\[\+\]\sAttack\saborted\.\sExiting/ nocase ascii wide
                        $string8 = /\[\+\]\sGetting\scredentials\susing\sU2U/ nocase ascii wide
                        $string9 = /\[\+\]\sImporting\sticket\sinto\sa\ssacrificial\sprocess\susing\sCreateNetOnly/ nocase ascii wide
                        $string10 = /\[\+\]\sPerforming\srecursive\sShadowSpray\sattack\.\sThis\smight\stake\sa\swhile/ nocase ascii wide
                        $string11 = /\[\+\]\sShadowSpray\srecovered\s/ nocase ascii wide
                        $string12 = /\\ShadowSpray\.cs/ nocase ascii wide
                        $string13 = /\\ShadowSpray\.sln/ nocase ascii wide
                        $string14 = /\\ShadowSpray\\.{0,1000}\.cs/ nocase ascii wide
                        $string15 = "1b6d6a1a116e8ddaeb7e3dde5dfc285e50004be80e977aa612447275c5930281" nocase ascii wide
                        $string16 = "2fd04964c571de856492e42f27043367c4b8e452a7f4719a1bdb0470b2b6576c" nocase ascii wide
                        $string17 = "7E47D586-DDC6-4382-848C-5CF0798084E1" nocase ascii wide
                        $string18 = "7E47D586-DDC6-4382-848C-5CF0798084E1" nocase ascii wide
                        $string19 = "837f6333561b575fc379d692f6f197a375feabb6c942170e262d36ef21709325" nocase ascii wide
                        $string20 = /attacker\.shadowCredObjects\.Count/ nocase ascii wide
                        $string21 = "CN=ShadowSpray" nocase ascii wide
                        $string22 = "Dec0ne/ShadowSpray" nocase ascii wide
                        $string23 = /Options\.shadowCredCertificatePassword/ nocase ascii wide
                        $string24 = "Performing recursive ShadowSpray attack" nocase ascii wide
                        $string25 = /shadowCredObject\.NTHash/ nocase ascii wide
                        $string26 = /shadowCredObject\.samAccountName/ nocase ascii wide
                        $string27 = "ShadowSpray recovered" nocase ascii wide
                        $string28 = /ShadowSpray\.Asn1/ nocase ascii wide
                        $string29 = /ShadowSpray\.exe/ nocase ascii wide
                        $string30 = /ShadowSpray\.exe/ nocase ascii wide
                        $string31 = /ShadowSpray\.Kerb/ nocase ascii wide
                        $string32 = /ShadowSpray\.Kerb\/1\.0/ nocase ascii wide
                        $string33 = /ShadowSpray\.sln/ nocase ascii wide
                        $string34 = "ShadowSpray-master" nocase ascii wide
                        $string35 = "ShorSec/ShadowSpray" nocase ascii wide

    condition:
        any of them
}
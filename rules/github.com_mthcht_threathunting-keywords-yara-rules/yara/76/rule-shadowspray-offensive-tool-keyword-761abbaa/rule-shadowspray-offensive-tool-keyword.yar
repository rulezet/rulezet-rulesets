rule rule_ShadowSpray_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ShadowSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShadowSpray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ShadowSpray_offensive_tool_keyword = " - ShadowSpray" nocase ascii wide
                        $string2_ShadowSpray_offensive_tool_keyword = " --RestoreShadowCred" nocase ascii wide
                        $string3_ShadowSpray_offensive_tool_keyword = /\/ShadowSpray\.git/ nocase ascii wide
                        $string4_ShadowSpray_offensive_tool_keyword = /\/ShadowSpray\.git/ nocase ascii wide
                        $string5_ShadowSpray_offensive_tool_keyword = /\/ShadowSpray\/.{0,1000}\.cs/ nocase ascii wide
                        $string6_ShadowSpray_offensive_tool_keyword = /\[\!\]\sUnhandled\sShadowSpray\.Kerb\sexception\:/ nocase ascii wide
                        $string7_ShadowSpray_offensive_tool_keyword = /\[\+\]\sAttack\saborted\.\sExiting/ nocase ascii wide
                        $string8_ShadowSpray_offensive_tool_keyword = /\[\+\]\sGetting\scredentials\susing\sU2U/ nocase ascii wide
                        $string9_ShadowSpray_offensive_tool_keyword = /\[\+\]\sImporting\sticket\sinto\sa\ssacrificial\sprocess\susing\sCreateNetOnly/ nocase ascii wide
                        $string10_ShadowSpray_offensive_tool_keyword = /\[\+\]\sPerforming\srecursive\sShadowSpray\sattack\.\sThis\smight\stake\sa\swhile/ nocase ascii wide
                        $string11_ShadowSpray_offensive_tool_keyword = /\[\+\]\sShadowSpray\srecovered\s/ nocase ascii wide
                        $string12_ShadowSpray_offensive_tool_keyword = /\\ShadowSpray\.cs/ nocase ascii wide
                        $string13_ShadowSpray_offensive_tool_keyword = /\\ShadowSpray\.sln/ nocase ascii wide
                        $string14_ShadowSpray_offensive_tool_keyword = /\\ShadowSpray\\.{0,1000}\.cs/ nocase ascii wide
                        $string15_ShadowSpray_offensive_tool_keyword = "1b6d6a1a116e8ddaeb7e3dde5dfc285e50004be80e977aa612447275c5930281" nocase ascii wide
                        $string16_ShadowSpray_offensive_tool_keyword = "2fd04964c571de856492e42f27043367c4b8e452a7f4719a1bdb0470b2b6576c" nocase ascii wide
                        $string17_ShadowSpray_offensive_tool_keyword = "7E47D586-DDC6-4382-848C-5CF0798084E1" nocase ascii wide
                        $string18_ShadowSpray_offensive_tool_keyword = "7E47D586-DDC6-4382-848C-5CF0798084E1" nocase ascii wide
                        $string19_ShadowSpray_offensive_tool_keyword = "837f6333561b575fc379d692f6f197a375feabb6c942170e262d36ef21709325" nocase ascii wide
                        $string20_ShadowSpray_offensive_tool_keyword = /attacker\.shadowCredObjects\.Count/ nocase ascii wide
                        $string21_ShadowSpray_offensive_tool_keyword = "CN=ShadowSpray" nocase ascii wide
                        $string22_ShadowSpray_offensive_tool_keyword = "Dec0ne/ShadowSpray" nocase ascii wide
                        $string23_ShadowSpray_offensive_tool_keyword = /Options\.shadowCredCertificatePassword/ nocase ascii wide
                        $string24_ShadowSpray_offensive_tool_keyword = "Performing recursive ShadowSpray attack" nocase ascii wide
                        $string25_ShadowSpray_offensive_tool_keyword = /shadowCredObject\.NTHash/ nocase ascii wide
                        $string26_ShadowSpray_offensive_tool_keyword = /shadowCredObject\.samAccountName/ nocase ascii wide
                        $string27_ShadowSpray_offensive_tool_keyword = "ShadowSpray recovered" nocase ascii wide
                        $string28_ShadowSpray_offensive_tool_keyword = /ShadowSpray\.Asn1/ nocase ascii wide
                        $string29_ShadowSpray_offensive_tool_keyword = /ShadowSpray\.exe/ nocase ascii wide
                        $string30_ShadowSpray_offensive_tool_keyword = /ShadowSpray\.exe/ nocase ascii wide
                        $string31_ShadowSpray_offensive_tool_keyword = /ShadowSpray\.Kerb/ nocase ascii wide
                        $string32_ShadowSpray_offensive_tool_keyword = /ShadowSpray\.Kerb\/1\.0/ nocase ascii wide
                        $string33_ShadowSpray_offensive_tool_keyword = /ShadowSpray\.sln/ nocase ascii wide
                        $string34_ShadowSpray_offensive_tool_keyword = "ShadowSpray-master" nocase ascii wide
                        $string35_ShadowSpray_offensive_tool_keyword = "ShorSec/ShadowSpray" nocase ascii wide

    condition:
        any of them
}
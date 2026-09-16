rule rule_RemoteKrbRelay_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RemoteKrbRelay' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RemoteKrbRelay"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RemoteKrbRelay_offensive_tool_keyword = /\s\.exe\s\-addgroupmember\s\-victim\s.{0,1000}\s\-target\s/ nocase ascii wide
                        $string2_RemoteKrbRelay_offensive_tool_keyword = /\s\.exe\s\-chp\s\-victim\s.{0,1000}\s\-target\s/ nocase ascii wide
                        $string3_RemoteKrbRelay_offensive_tool_keyword = /\s\.exe\s\-laps\s\-victim\s.{0,1000}\s\-target\s.{0,1000}\s\-clsid\s/ nocase ascii wide
                        $string4_RemoteKrbRelay_offensive_tool_keyword = /\s\.exe\s\-ldapwhoami\s\-victim\s.{0,1000}\s\-target\s.{0,1000}\s\-clsid\s/ nocase ascii wide
                        $string5_RemoteKrbRelay_offensive_tool_keyword = /\s\.exe\s\-rbcd\s\-victim\s.{0,1000}\s\-target\s.{0,1000}\s\-clsid\s/ nocase ascii wide
                        $string6_RemoteKrbRelay_offensive_tool_keyword = " -forceshadowcred " nocase ascii wide
                        $string7_RemoteKrbRelay_offensive_tool_keyword = " -local dc011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAAA" nocase ascii wide
                        $string8_RemoteKrbRelay_offensive_tool_keyword = " -shadowcred -victim " nocase ascii wide
                        $string9_RemoteKrbRelay_offensive_tool_keyword = /\s\-smb\s\-\-smbkeyword\s.{0,1000}\s\-victim\s/ nocase ascii wide
                        $string10_RemoteKrbRelay_offensive_tool_keyword = /\sSystem\saccount\.\sOn\svictim\scomputer\sshould\sbe\sinstalled\sAD\sCS/ nocase ascii wide
                        $string11_RemoteKrbRelay_offensive_tool_keyword = " --victimdn " nocase ascii wide
                        $string12_RemoteKrbRelay_offensive_tool_keyword = /\/RemoteKrbRelay\.git/ nocase ascii wide
                        $string13_RemoteKrbRelay_offensive_tool_keyword = /\[\!\]\sDont\sforget\sabout\sadding\syour\sattack\sin\sAcceptSecurityContext\(/ nocase ascii wide
                        $string14_RemoteKrbRelay_offensive_tool_keyword = /\[\!\]\sI\swill\sdump\sall\scomputer\spasswords/ nocase ascii wide
                        $string15_RemoteKrbRelay_offensive_tool_keyword = /\[\!\]\sPlease\sspecify\ssmb\sattack\skeyword\s\-\-smbkeyword\s/ nocase ascii wide
                        $string16_RemoteKrbRelay_offensive_tool_keyword = /\[\-\]\sGot\serror\s\'LDAP_INSUFFICIENT_ACCESS\'\swhen\strying\sto\sadd\snew\sKeyCredential/ nocase ascii wide
                        $string17_RemoteKrbRelay_offensive_tool_keyword = /\[\+\]\sClearing\smsDS\-KeyCredentialLink\sbefore\sadding\sour\snew\sKeyCredential/ nocase ascii wide
                        $string18_RemoteKrbRelay_offensive_tool_keyword = /\[\+\]\sGot\sKrb\sAuth\sfrom\sNT\/System\.\sRelaying\sto\sADCS\snow/ nocase ascii wide
                        $string19_RemoteKrbRelay_offensive_tool_keyword = /\\\\windows\\\\temp\\\\sam\.tmp/ nocase ascii wide
                        $string20_RemoteKrbRelay_offensive_tool_keyword = /\\\\windows\\\\temp\\\\sys\.tmp/ nocase ascii wide
                        $string21_RemoteKrbRelay_offensive_tool_keyword = /\\Checkerv2\.0\.exe\s\-outfile\s.{0,1000}\s\-outformat\s/ nocase ascii wide
                        $string22_RemoteKrbRelay_offensive_tool_keyword = /\\RemoteKrbRelay\\/ nocase ascii wide
                        $string23_RemoteKrbRelay_offensive_tool_keyword = /\\RemoteKrbRelay\-main/ nocase ascii wide
                        $string24_RemoteKrbRelay_offensive_tool_keyword = /\\windows\\\\temp\\\\sec\.tmp/ nocase ascii wide
                        $string25_RemoteKrbRelay_offensive_tool_keyword = /\\windows\\temp\\sam\.tmp/ nocase ascii wide
                        $string26_RemoteKrbRelay_offensive_tool_keyword = /\\windows\\temp\\sec\.tmp/ nocase ascii wide
                        $string27_RemoteKrbRelay_offensive_tool_keyword = /\\windows\\temp\\sys\.tmp/ nocase ascii wide
                        $string28_RemoteKrbRelay_offensive_tool_keyword = "0db0228defb8d913de486d4f799be97bc75b5aa2ae72c2fc1e99389aeb92b170" nocase ascii wide
                        $string29_RemoteKrbRelay_offensive_tool_keyword = "3b3b3491978395ddceeab0ee18aa25ae8fcb1a8df43ef80ab4423517e9c5f566" nocase ascii wide
                        $string30_RemoteKrbRelay_offensive_tool_keyword = "41d38b945928ee53bd8b1f3b230ecf3101f6c2249d1ec4d3d920a163045373b8" nocase ascii wide
                        $string31_RemoteKrbRelay_offensive_tool_keyword = "5494EDD3-132D-4238-AC25-FA384D78D4E3" nocase ascii wide
                        $string32_RemoteKrbRelay_offensive_tool_keyword = "79806039befe2c12c794ab8951aa17edf316843a8b968d22bd7abc9937252014" nocase ascii wide
                        $string33_RemoteKrbRelay_offensive_tool_keyword = "8d43a02d409a31297b2d1a997dbeaeaf10f97f499e2da819eef1318c0df652e4" nocase ascii wide
                        $string34_RemoteKrbRelay_offensive_tool_keyword = "8d7870f61a93a1466b02cad2cc5c036e1a7dc76753a6b90a38f41a6558c65146" nocase ascii wide
                        $string35_RemoteKrbRelay_offensive_tool_keyword = "906a7f9794d035af75552674eaa775b1584a129d1cd16d49c15bb5aa8032661a" nocase ascii wide
                        $string36_RemoteKrbRelay_offensive_tool_keyword = "B00DC126-D32B-429F-9BB5-97AF33BEE0E1" nocase ascii wide
                        $string37_RemoteKrbRelay_offensive_tool_keyword = "BC74B071-B36A-4EE8-8F03-5CF0A02C32DA" nocase ascii wide
                        $string38_RemoteKrbRelay_offensive_tool_keyword = "c973abdd59e75eda169065c64631477fa9ad6f01e3536d6f0754c27d0aeeec72" nocase ascii wide
                        $string39_RemoteKrbRelay_offensive_tool_keyword = "CICADA8 Research Team" nocase ascii wide
                        $string40_RemoteKrbRelay_offensive_tool_keyword = "CICADA8-Research/RemoteKrbRelay" nocase ascii wide
                        $string41_RemoteKrbRelay_offensive_tool_keyword = "F8317556-F82B-4FE2-9857-3E8DE896AA32" nocase ascii wide
                        $string42_RemoteKrbRelay_offensive_tool_keyword = "f96112996f7f6cc45c382096b622d7b8b909c38c116affbdb8cdd26f890763d2" nocase ascii wide
                        $string43_RemoteKrbRelay_offensive_tool_keyword = /FindAvailablePort\.exe/ nocase ascii wide
                        $string44_RemoteKrbRelay_offensive_tool_keyword = /From\sMichael\sZhmaylo\s\(MzHmO\)/ nocase ascii wide
                        $string45_RemoteKrbRelay_offensive_tool_keyword = /RemoteKrbRelay\.exe/ nocase ascii wide
                        $string46_RemoteKrbRelay_offensive_tool_keyword = "Small tool that allow you to bypass the firewall during COM operations" nocase ascii wide

    condition:
        any of them
}
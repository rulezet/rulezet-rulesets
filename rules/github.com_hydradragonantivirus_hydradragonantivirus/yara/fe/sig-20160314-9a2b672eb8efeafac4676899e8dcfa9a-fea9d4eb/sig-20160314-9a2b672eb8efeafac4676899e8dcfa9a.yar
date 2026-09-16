rule sig_20160314_9a2b672eb8efeafac4676899e8dcfa9a {
  meta:
    description = "datamaliciousorder - file 20160314_9a2b672eb8efeafac4676899e8dcfa9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a1036d933f2c93ba0acc2df6eaa139360f1e30974034ab481a8b5d6ab4fe6e6"

  strings:
    $s1  = "var sz = true  , cnaY = mPs[7] + mPs[9] + mPs[11];" fullword ascii
    $s2  = "return oHEwbEo[0] + oHEwbEo[2] + oHEwbEo[4] + \".F\" + oHEwbEo[7] + oHEwbEo[9] + oHEwbEo[12] + oHEwbEo[14];" fullword ascii
    $s3  = "zKOiy.open(mpmrg,VAqCc,false);" fullword ascii
    $s4  = "var oHEwbEo = \"Sc rjkJtmq r iTUTUgJEJ ipting JxOoxmG WVI ile rXMvMezUwoTWRt System ju xOlGF Obj gDNTrr ect xDZuzAs jDAjQ\".spli" ascii
    $s5  = "var oHEwbEo = \"Sc rjkJtmq r iTUTUgJEJ ipting JxOoxmG WVI ile rXMvMezUwoTWRt System ju xOlGF Obj gDNTrr ect xDZuzAs jDAjQ\".spli" ascii
    $s6  = "var mPs = (\"2.XMLHTTP gzOuCox BETrp XML ream St dwJfoUKN AD reVnhUl O EThV D\").split(\" \");" fullword ascii
    $s7  = "function JxGh(oWQka,UZLoA) {" fullword ascii
    $s8  = "return new ActiveXObject(NOOjys);" fullword ascii
    $s9  = "function ZhqZNLP(RPou,bPCvb) {" fullword ascii
    $s10 = "return ZhqZNLP(hW,qnAnc[172-166]+qnAnc[635-628]+qnAnc[757-749]);" fullword ascii
    $s11 = "VGJ = e; break; " fullword ascii
    $s12 = "function gasJ(cfwTa) {" fullword ascii
    $s13 = "if (TEfHe == 788-588){return true;} else {return false;}" fullword ascii
    $s14 = "function dFjX(zKOiy,VAqCc,mpmrg) {" fullword ascii
    $s15 = "function GAYc(TEfHe) {" fullword ascii
    $s16 = "return gVR.size;" fullword ascii
    $s17 = "function JsrMgCYS() {" fullword ascii
    $s18 = "if (MAfOk > 168571-169){return true;} else {return false;}" fullword ascii
    $s19 = "return RPou.ExpandEnvironmentStrings(bPCvb);" fullword ascii
    $s20 = "function UcnBJCRs(gVR) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
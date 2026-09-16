rule sig_20160323_0a8c567288888e521a8e28c1b445725e {
  meta:
    description = "datamaliciousorder - file 20160323_0a8c567288888e521a8e28c1b445725e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7498fbe10161c7677bfd6224bfc138eccf5c3803be9a47d5ba5169c11e96747"

  strings:
    $s1  = "return WScript.CreateObject(pBoSt);" fullword ascii
    $s2  = "var LcT = HdxB(DOmy + \"B.\" + iYY[5]+(77465, iYY[4]));" fullword ascii
    $s3  = "return vrBZkhf[0] + vrBZkhf[2] + vrBZkhf[4] + \".F\" + vrBZkhf[7] + vrBZkhf[9] + vrBZkhf[12] + vrBZkhf[14];" fullword ascii
    $s4  = "var Mb = true  , DOmy = iYY[7] + iYY[9] + iYY[11];" fullword ascii
    $s5  = "var vrBZkhf = alVgb(CsKDrrJiUO+\" \"+\"System lt RgfOh Obj XoWEGF ect FItffxX MrFhG\", \" \");" fullword ascii
    $s6  = "MgRL.open(dhseY,WYlWl,false);" fullword ascii
    $s7  = "var iYY = (\"2.XMLHTTP rNovmTS fYwKL XML ream St ltqEmcip AD OmnlcxY O akKk D\").split(\" \");" fullword ascii
    $s8  = "function alVgb(Xin,cmkHP) {" fullword ascii
    $s9  = "function kjiMf(nmSdMI) {" fullword ascii
    $s10 = "function IcsG(EHMcq) {" fullword ascii
    $s11 = "function soJz(dKQzW,bvfCp) {" fullword ascii
    $s12 = "function ibheESc(aBjF) {" fullword ascii
    $s13 = "JOF = k; break; " fullword ascii
    $s14 = "return Xin.split(cmkHP);" fullword ascii
    $s15 = "function kjZx(ApPSa) {" fullword ascii
    $s16 = "if(k>=P.length) {break;}" fullword ascii
    $s17 = "function nIXzH(iXjyPE) {" fullword ascii
    $s18 = "if (UlhMl == 662-462){return true;} else {return false;}" fullword ascii
    $s19 = "return new ActiveXObject(EWYK);" fullword ascii
    $s20 = "return dpgWLdp(kG,uZoYB[223-217]+uZoYB[402-395]+uZoYB[377-369]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
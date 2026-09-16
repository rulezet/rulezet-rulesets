rule sig_20160314_41e309ad848430447cb700f4fc494161 {
  meta:
    description = "datamaliciousorder - file 20160314_41e309ad848430447cb700f4fc494161.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c7a6649f80107e8077d84f754ada3c286393d9cf261eacc6de82c4c2c0368a5"

  strings:
    $s1  = "return vZwEeYe" fullword ascii
    $s2  = "var HW = true  , DBBd = wQx[7] + wQx[9] + wQx[11];" fullword ascii
    $s3  = "return KmZxkkk[0] + KmZxkkk[2] + KmZxkkk[4] + \".F\" + KmZxkkk[7] + KmZxkkk[9] + KmZxkkk[12] + KmZxkkk[14];" fullword ascii
    $s4  = "vPAGJ.open(fQokw,EvwaJ,false);" fullword ascii
    $s5  = "var KmZxkkk = \"Sc reuVlJx r rJhmdtpDq ipting PJbtKIk ICd ile FsyuCLysbCgXrH System EG jBfIU Obj IYIdjb ect UEsKHKc FoedL\".spli" ascii
    $s6  = "var wQx = (\"2.XMLHTTP CgUvVZB QiZdB XML ream St pkmTmIHW AD SUqLUHL O JqUT D\").split(\" \");" fullword ascii
    $s7  = "var KmZxkkk = \"Sc reuVlJx r rJhmdtpDq ipting PJbtKIk ICd ile FsyuCLysbCgXrH System EG jBfIU Obj IYIdjb ect UEsKHKc FoedL\".spli" ascii
    $s8  = "if(H>=h.length) {break;}" fullword ascii
    $s9  = "return new ActiveXObject(KhiDLv);" fullword ascii
    $s10 = "function oTmNbsAt(XQz) {" fullword ascii
    $s11 = "function eOIu(vPAGJ,EvwaJ,fQokw) {" fullword ascii
    $s12 = "function UrYRBFh(Oepj,UMkms) {" fullword ascii
    $s13 = "function ieVwd(UaUfKe) {" fullword ascii
    $s14 = "function TPqL(GhHiH) {" fullword ascii
    $s15 = "function kKNC(JecvS) {" fullword ascii
    $s16 = "return ZQAIC;" fullword ascii
    $s17 = "function CTSAjKq(OPrU) {" fullword ascii
    $s18 = "function CCFq(jaliw) {" fullword ascii
    $s19 = "return OPrU.responseBody;" fullword ascii
    $s20 = "return UrYRBFh(hE,XyGzo[855-849]+XyGzo[244-237]+XyGzo[257-249]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
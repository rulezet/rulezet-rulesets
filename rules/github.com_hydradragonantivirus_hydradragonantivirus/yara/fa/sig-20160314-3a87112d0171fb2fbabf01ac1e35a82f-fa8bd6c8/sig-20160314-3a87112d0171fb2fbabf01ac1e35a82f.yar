rule sig_20160314_3a87112d0171fb2fbabf01ac1e35a82f {
  meta:
    description = "datamaliciousorder - file 20160314_3a87112d0171fb2fbabf01ac1e35a82f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd7c82302227c6d0818eb0f8488bd8e7407e9219676989e7f3102c20d5df0276"

  strings:
    $s1  = "return eCqKtHo[0] + eCqKtHo[2] + eCqKtHo[4] + \".F\" + eCqKtHo[7] + eCqKtHo[9] + eCqKtHo[12] + eCqKtHo[14];" fullword ascii
    $s2  = "var rG = true  , hfbn = qHH[7] + qHH[9] + qHH[11];" fullword ascii
    $s3  = "eIzHD.open(HFLUU,xcEdz,false);" fullword ascii
    $s4  = "var qHH = (\"2.XMLHTTP QRhWBle iKRrQ XML ream St UqnVCtzs AD EPWzBKl O zaFF D\").split(\" \");" fullword ascii
    $s5  = "function Dbawu(rdMoTT) {" fullword ascii
    $s6  = "function XmsVB(nmOplP) {" fullword ascii
    $s7  = "function TCfJ(zZNVS) {" fullword ascii
    $s8  = "return Zdkt.responseBody;" fullword ascii
    $s9  = "if (s >= Cnmym.length) {break;}" fullword ascii
    $s10 = "function LDMR(bnMLj) {" fullword ascii
    $s11 = "if (xnMiW == 1161-961){return true;} else {return false;}" fullword ascii
    $s12 = "function CThaEtKR() {" fullword ascii
    $s13 = "return ASbYT;" fullword ascii
    $s14 = "function FDdW(eIzHD,xcEdz,HFLUU) {" fullword ascii
    $s15 = "if(I>=l.length) {break;}" fullword ascii
    $s16 = "function pUyJAwTj(Wno) {" fullword ascii
    $s17 = "return aYxmfEa(nX,EHQaG[635-629]+EHQaG[623-616]+EHQaG[173-165]);" fullword ascii
    $s18 = "return RNjzZuf" fullword ascii
    $s19 = "function EOAp(xISDd,WMTdA) {" fullword ascii
    $s20 = "function aYxmfEa(aZCB,EMUHq) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
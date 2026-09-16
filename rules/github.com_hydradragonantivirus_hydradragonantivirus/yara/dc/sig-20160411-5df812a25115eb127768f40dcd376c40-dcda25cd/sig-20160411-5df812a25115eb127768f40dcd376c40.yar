rule sig_20160411_5df812a25115eb127768f40dcd376c40 {
  meta:
    description = "datamaliciousorder - file 20160411_5df812a25115eb127768f40dcd376c40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b874cab73d10d566fbfe1e7f2f4898a083deb129a18ef409aeafc927863a7cf5"

  strings:
    $s1  = "return YClKgSF[0] + YClKgSF[2] + YClKgSF[4] + \".F\" + YClKgSF[7] + YClKgSF[9] + YClKgSF[12] + YClKgSF[14];" fullword ascii
    $s2  = "var JJ = true  , lZUf = tjk[7] + tjk[9] + tjk[11];" fullword ascii
    $s3  = "gpYt.open(jjJtl,iOlIV,false);" fullword ascii
    $s4  = "var tjk = (\"2.XMLHTTP HHwKBlb swUfV XML ream St YASrFuyS AD uvJPwPW O hBgU D\").split(\" \");" fullword ascii
    $s5  = "if(C>=I.length) {break;}" fullword ascii
    $s6  = "function vDjS(kDvjX,lMecI) {" fullword ascii
    $s7  = "function aEyNdo(OCfxgky) {" fullword ascii
    $s8  = "function ONttZH(PMZA,hViRUM) {" fullword ascii
    $s9  = "function xCxE(UlSKX,iOlIV,jjJtl) {" fullword ascii
    $s10 = "function OKTe(liPXJ) {" fullword ascii
    $s11 = "function RrWMs(CklAlW) {" fullword ascii
    $s12 = "if (liPXJ == 1161-961){return true;} else {return false;}" fullword ascii
    $s13 = "function eSEF(FbfuQ) {" fullword ascii
    $s14 = "function sNcZvZp(ZvSo) {" fullword ascii
    $s15 = "return new ActiveXObject(OCsc);" fullword ascii
    $s16 = "if (d >= HRwoh.length) {break;}" fullword ascii
    $s17 = "function YvPrLTiD(IHf) {" fullword ascii
    $s18 = "return VgmGXks;" fullword ascii
    $s19 = "function ieiB(OVuuJ) {" fullword ascii
    $s20 = "function IbFHHoU(HzKn,kBFxb) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
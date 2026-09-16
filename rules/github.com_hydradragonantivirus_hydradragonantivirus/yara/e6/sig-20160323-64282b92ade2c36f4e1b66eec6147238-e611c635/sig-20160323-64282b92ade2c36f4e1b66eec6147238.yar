rule sig_20160323_64282b92ade2c36f4e1b66eec6147238 {
  meta:
    description = "datamaliciousorder - file 20160323_64282b92ade2c36f4e1b66eec6147238.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb6c492cb7ba392ac976f81eb502aa0065a341c8974fa0fee16e69708c8cd158"

  strings:
    $s1  = "return WScript.CreateObject(BMlME);" fullword ascii
    $s2  = "return rtMWFce[0] + rtMWFce[2] + rtMWFce[4] + \".F\" + rtMWFce[7] + rtMWFce[9] + rtMWFce[12] + rtMWFce[14];" fullword ascii
    $s3  = "var IE = true  , rSwD = VtI[7] + VtI[9] + VtI[11];" fullword ascii
    $s4  = "JzTO.open(jADPi,GqSmp,false);" fullword ascii
    $s5  = "var rtMWFce = rTVyk(VnGrkurXjt+\" \"+\"System kk WKxyH Obj UjRLDX ect mVrfTsc TdHEV\", \" \");" fullword ascii
    $s6  = "var VtI = (\"2.XMLHTTP RZaAMtA ylYxm XML ream St ugKsPdnZ AD HDiDumb O rbUQ D\").split(\" \");" fullword ascii
    $s7  = "if(F>=T.length) {break;}" fullword ascii
    $s8  = "function rTVyk(oue,NhxKv) {" fullword ascii
    $s9  = "function eaEx(Eekwn) {" fullword ascii
    $s10 = "if (Eekwn == 609-409){return true;} else {return false;}" fullword ascii
    $s11 = "function KhuNXhlM(TaH) {" fullword ascii
    $s12 = "function jtwY(ZiaUe) {" fullword ascii
    $s13 = "function APUR(BMlME) {" fullword ascii
    $s14 = "function UCKbzSdA(yHEb) {" fullword ascii
    $s15 = "function ByHz(WiRRS,hWnMR) {" fullword ascii
    $s16 = "lNf = F; break; " fullword ascii
    $s17 = "function WMwT(LNrJj) {" fullword ascii
    $s18 = "function jHqUB(oZRzmo) {" fullword ascii
    $s19 = "return ZiaUe.status;" fullword ascii
    $s20 = "function OtxB(bJPdE) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
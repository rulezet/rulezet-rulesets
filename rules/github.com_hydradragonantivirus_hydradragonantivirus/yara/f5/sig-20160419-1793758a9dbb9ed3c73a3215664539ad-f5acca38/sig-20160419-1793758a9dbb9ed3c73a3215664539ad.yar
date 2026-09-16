rule sig_20160419_1793758a9dbb9ed3c73a3215664539ad {
  meta:
    description = "datamaliciousorder - file 20160419_1793758a9dbb9ed3c73a3215664539ad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07b7ca803d8d17c17778852ac7f0737ae834d8a4e9157428f51ac4f1d15b211a"

  strings:
    $s1  = "var Kl = true  , hMdN = BOO[7] + BOO[9] + BOO[11];" fullword ascii
    $s2  = "return hNyvOFI[0] + hNyvOFI[2] + hNyvOFI[4] + \".F\" + hNyvOFI[7] + hNyvOFI[9] + hNyvOFI[12] + hNyvOFI[14];" fullword ascii
    $s3  = "var BOO = (\"2.XMLHTTP XQUAqMV Hkowr XML ream St KkIAFjfc AD PoOsSNo O lIab D\").split(\" \");" fullword ascii
    $s4  = "dkes.open(uwZXU,Hbmvp,false);" fullword ascii
    $s5  = "if(N>=x.length) {break;}" fullword ascii
    $s6  = "function JXYi(fDuBP,fXXCm) {" fullword ascii
    $s7  = "return TUcif;" fullword ascii
    $s8  = "function QTAd(BJrqe,Hbmvp,uwZXU) {" fullword ascii
    $s9  = "function agMWRMJRZ(pKlFU) {" fullword ascii
    $s10 = "function dpFu(ukbwm) {" fullword ascii
    $s11 = "return OqReKAg;" fullword ascii
    $s12 = "function tIVEtNAQ(FkGa) {" fullword ascii
    $s13 = "function crgkYfvF(qOw) {" fullword ascii
    $s14 = "return wUpHDmk(RA,PwqUlB+Mstkc[473-465]);" fullword ascii
    $s15 = "return vqDpZRi[0];" fullword ascii
    $s16 = "function hQCZ(psnQi) {" fullword ascii
    $s17 = "ovD = N; break; " fullword ascii
    $s18 = "return kFhp[KnrOuvg[0]+KnrOuvg[1]];" fullword ascii
    $s19 = "return new ActiveXObject(XguJ);" fullword ascii
    $s20 = "if (ukbwm != 1113-913){return false;} else {return true;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
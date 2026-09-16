rule sig_20160404_a36775babaa4572a83f144c65cd364fd {
  meta:
    description = "datamaliciousorder - file 20160404_a36775babaa4572a83f144c65cd364fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cf8cf3fdc16350bb03570c986248c898f49d636cf7f04b931aca253d6f070de"

  strings:
    $s1  = "var Jx = true  , CdTz = DEy[7] + DEy[9] + DEy[11];" fullword ascii
    $s2  = "return QxIDnDe[0] + QxIDnDe[2] + QxIDnDe[4] + \".F\" + QxIDnDe[7] + QxIDnDe[9] + QxIDnDe[12] + QxIDnDe[14];" fullword ascii
    $s3  = "var QxIDnDe = GyrIk(GRacIPDakZ+\" \"+\"System wU RjPYM Obj UMWKma ect jSVMtEG HcNzR\", \" \");" fullword ascii
    $s4  = "EaXc.open(liswp,kEIYy,false);" fullword ascii
    $s5  = "if (CqBZR > 159868-109){return true;} else {return false;}" fullword ascii
    $s6  = "function EqgErZY(CQMN) {" fullword ascii
    $s7  = "var INBXoQr = \"JwLlmt*Hst*pt.S\"+\"hell*haAuPoL*Scri*\";" fullword ascii
    $s8  = "function dFtg(MCFaE) {" fullword ascii
    $s9  = "return jUs.size;" fullword ascii
    $s10 = "function bcmBsw(mqkF,xFbKGz) {" fullword ascii
    $s11 = "eup = U; break; " fullword ascii
    $s12 = "return mCcVP.status;" fullword ascii
    $s13 = "function FsdXd(wIINqyXD,IZpp) {" fullword ascii
    $s14 = "return ULiNJ;" fullword ascii
    $s15 = "return uVk.split(VgEbv);" fullword ascii
    $s16 = "function lPDh(mCcVP) {" fullword ascii
    $s17 = "function sESz(CqBZR) {" fullword ascii
    $s18 = "function UgXrIhem(jUs) {" fullword ascii
    $s19 = "function JXpw(vhPpa) {" fullword ascii
    $s20 = "return CQMN[YqJTgj[0]];" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
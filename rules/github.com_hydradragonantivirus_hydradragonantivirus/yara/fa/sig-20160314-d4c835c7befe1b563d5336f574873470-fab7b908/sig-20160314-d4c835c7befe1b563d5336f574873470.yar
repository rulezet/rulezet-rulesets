rule sig_20160314_d4c835c7befe1b563d5336f574873470 {
  meta:
    description = "datamaliciousorder - file 20160314_d4c835c7befe1b563d5336f574873470.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9cd92d1dea7d4fe9e1b0ac54bdd3d46f987b66ab0a84454b7ecc1ea7f1dfeb83"

  strings:
    $s1  = "var BR = true  , qRvO = CQP[7] + CQP[9] + CQP[11];" fullword ascii
    $s2  = "return kRWpPIX[0] + kRWpPIX[2] + kRWpPIX[4] + \".F\" + kRWpPIX[7] + kRWpPIX[9] + kRWpPIX[12] + kRWpPIX[14];" fullword ascii
    $s3  = "var CQP = (\"2.XMLHTTP gUzfePM aIufe XML ream St eSQNefmk AD kbOvYZX O zMvo D\").split(\" \");" fullword ascii
    $s4  = "var kRWpPIX = \"Sc SRIBnuG r wLNytvhTa ipting YzUGmlF LER ile LQyJguVrZtjeoU System sU yhsXl Obj IKUPaa ect lWrfjlD cUnJN\".spli" ascii
    $s5  = "var kRWpPIX = \"Sc SRIBnuG r wLNytvhTa ipting YzUGmlF LER ile LQyJguVrZtjeoU System sU yhsXl Obj IKUPaa ect lWrfjlD cUnJN\".spli" ascii
    $s6  = "hrRcS.open(SBnPG,CjNvZ,false);" fullword ascii
    $s7  = "return trrUzxA" fullword ascii
    $s8  = "return fhjyx.status;" fullword ascii
    $s9  = "return eLs.size;" fullword ascii
    $s10 = "function riLj(hrRcS,CjNvZ,SBnPG) {" fullword ascii
    $s11 = "function NJXb(sJFzo) {" fullword ascii
    $s12 = "function SQGcYbAmS(hORKQfTTGtN) {" fullword ascii
    $s13 = "function PYfnKwzTu() {" fullword ascii
    $s14 = "function umIa(fFHXY) {" fullword ascii
    $s15 = "function MDQF(NDjfd,wavDp) {" fullword ascii
    $s16 = "Khb = V; break; " fullword ascii
    $s17 = "function Wryy(fhjyx) {" fullword ascii
    $s18 = "return NVYRcyX(AF,qZmkU[977-971]+qZmkU[905-898]+qZmkU[262-254]);" fullword ascii
    $s19 = "function zNhIUQL(QgcF) {" fullword ascii
    $s20 = "function bgNvr(BDZBuk) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
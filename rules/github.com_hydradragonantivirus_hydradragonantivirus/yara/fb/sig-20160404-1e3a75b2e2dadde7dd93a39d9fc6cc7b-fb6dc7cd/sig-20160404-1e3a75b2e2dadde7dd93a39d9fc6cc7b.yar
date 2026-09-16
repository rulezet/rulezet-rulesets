rule sig_20160404_1e3a75b2e2dadde7dd93a39d9fc6cc7b {
  meta:
    description = "datamaliciousorder - file 20160404_1e3a75b2e2dadde7dd93a39d9fc6cc7b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd50aa5fb32013a647625450a334638970daf244f56160da426ebbd4c336ec5d"

  strings:
    $s1  = "var we = true  , aykQ = VYU[7] + VYU[9] + VYU[11];" fullword ascii
    $s2  = "return AxVOICg[0] + AxVOICg[2] + AxVOICg[4] + \".F\" + AxVOICg[7] + AxVOICg[9] + AxVOICg[12] + AxVOICg[14];" fullword ascii
    $s3  = "var VYU = (\"2.XMLHTTP qQnBkGT pNcVd XML ream St bJjsnNrx AD eAbSlsC O Rfbn D\").split(\" \");" fullword ascii
    $s4  = "LJsW.open(UIvDx,FuuHD,false);" fullword ascii
    $s5  = "var AxVOICg = hlgcL(xjNMlyoDJR+\" \"+\"System GR kTWaW Obj BNoDUE ect DdSnjfH EVmpT\", \" \");" fullword ascii
    $s6  = "if(H>=h.length) {break;}" fullword ascii
    $s7  = "if (AnIjY > 161914-144){return true;} else {return false;}" fullword ascii
    $s8  = "function xVoCb(aKNmVPpb,ByAV) {" fullword ascii
    $s9  = "function lyHnPtQg(sDwe) {" fullword ascii
    $s10 = "return KZw.split(TwZKt);" fullword ascii
    $s11 = "function yeukPPj(RVVU) {" fullword ascii
    $s12 = "function CwuQ(LdNeH) {" fullword ascii
    $s13 = "return nXJ.size;" fullword ascii
    $s14 = "function JydI(DRDWf) {" fullword ascii
    $s15 = "var HMONKhO = \"eXkBFN*lDp*pt.S\"+\"hell*szpkRFZ*Scri*\";" fullword ascii
    $s16 = "return RVVU[sqrdxg[0]];" fullword ascii
    $s17 = "if (c >= McmHj.length) {break;}" fullword ascii
    $s18 = "function UhVe(RbKCc) {" fullword ascii
    $s19 = "function GqHG(McmHj) {" fullword ascii
    $s20 = "function tjTj(FtmIL) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
rule sig_20160314_90ec01f5e67a97a8b8dd84838bc4071c {
  meta:
    description = "datamaliciousorder - file 20160314_90ec01f5e67a97a8b8dd84838bc4071c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e3822599cb904c0d548f51cfd99752af17958a6a842a86a68aebbb778721874"

  strings:
    $s1  = "return cptbaTH[0] + cptbaTH[2] + cptbaTH[4] + \".F\" + cptbaTH[7] + cptbaTH[9] + cptbaTH[12] + cptbaTH[14];" fullword ascii
    $s2  = "var dC = true  , sCFw = qMS[7] + qMS[9] + qMS[11];" fullword ascii
    $s3  = "var cptbaTH = \"Sc tbOkRGv r BDjVlwlLK ipting BJNhOjC HQF ile UOYUfCnKXqbraa System UY anjGz Obj wmsDBD ect RhMBwgH DPrdp\".spli" ascii
    $s4  = "fPTly.open(MctFd,oEMHy,false);" fullword ascii
    $s5  = "var qMS = (\"2.XMLHTTP lrhqpAc tIzXa XML ream St iChzfGvb AD LuFoVLC O Ilnm D\").split(\" \");" fullword ascii
    $s6  = "var cptbaTH = \"Sc tbOkRGv r BDjVlwlLK ipting BJNhOjC HQF ile UOYUfCnKXqbraa System UY anjGz Obj wmsDBD ect RhMBwgH DPrdp\".spli" ascii
    $s7  = "function wNxs(jZMxr) {" fullword ascii
    $s8  = "function QvasTeaG() {" fullword ascii
    $s9  = "function QgpK(zoDUB,Flkob) {" fullword ascii
    $s10 = "return vcXXe;" fullword ascii
    $s11 = "function Lmly(fvxgZ,LiHsm) {" fullword ascii
    $s12 = "return FyefFvH(xQ,Kyfuq[199-193]+Kyfuq[447-440]+Kyfuq[540-532]);" fullword ascii
    $s13 = "function rVDMy(ieWuPo) {" fullword ascii
    $s14 = "return ToDf.ExpandEnvironmentStrings(UOvUn);" fullword ascii
    $s15 = "if(n>=V.length) {break;}" fullword ascii
    $s16 = "return new ActiveXObject(xVXWab);" fullword ascii
    $s17 = "function DOGRLSCyj() {" fullword ascii
    $s18 = "function NsLu(ewabB) {" fullword ascii
    $s19 = "function NgKxYOH(BVHj) {" fullword ascii
    $s20 = "function hcJRBxHZ(zHJ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
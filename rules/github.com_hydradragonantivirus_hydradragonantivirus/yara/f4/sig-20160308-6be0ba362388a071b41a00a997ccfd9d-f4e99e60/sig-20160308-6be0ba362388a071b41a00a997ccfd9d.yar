rule sig_20160308_6be0ba362388a071b41a00a997ccfd9d {
  meta:
    description = "datamaliciousorder - file 20160308_6be0ba362388a071b41a00a997ccfd9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fad1ae0dd73a06b8b28f112b3d87103e2b8f10be754eb13d607d2266fca7bd63"

  strings:
    $s1  = "return emQvMPb[0] + emQvMPb[2] + emQvMPb[4] + \".F\" + emQvMPb[7] + emQvMPb[9] + emQvMPb[12] + emQvMPb[14];" fullword ascii
    $s2  = "var VJ = true  , efGT = htj[7] + htj[9] + htj[11];" fullword ascii
    $s3  = "PCquU.open(PJOQz,frSOE,false);" fullword ascii
    $s4  = "var htj = (\"2.XMLHTTP otExLOn PdQHl XML ream St parKMjOa AD vRurRHe O axqW D\").split(\" \");" fullword ascii
    $s5  = "var emQvMPb = \"Sc LsUSnBs r RtPjswjiH ipting iNWQAch xLZ ile FpMSDvolbyKhqj System vG JGqSi Obj EBFLIK ect gAhYvDu\".split(\" " ascii
    $s6  = "if (MUpCU == 323-123){return true;} else {return false;}" fullword ascii
    $s7  = "if (RjlXz > 176294-212){return true;} else {return false;}" fullword ascii
    $s8  = "return TlwCT;" fullword ascii
    $s9  = "return QldrVWj" fullword ascii
    $s10 = "return UCoU.responseBody;" fullword ascii
    $s11 = "function BwRLJxpC() {" fullword ascii
    $s12 = "function NNpG(DhtHa) {" fullword ascii
    $s13 = "function MCuq(cdGhE) {" fullword ascii
    $s14 = "function UuPD(PCquU,frSOE,PJOQz) {" fullword ascii
    $s15 = "function idElMHZ(UCoU) {" fullword ascii
    $s16 = "function uodY(lUhxl,SsnkC) {" fullword ascii
    $s17 = "function tusFhjvc(hlE) {" fullword ascii
    $s18 = "rCD = H; break; " fullword ascii
    $s19 = "function BXzM(iKnzb) {" fullword ascii
    $s20 = "function mjIY(AMnzI,pahdy) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
rule sig_20160404_1d92ec4eb4207c9fb21121d9278a5099 {
  meta:
    description = "datamaliciousorder - file 20160404_1d92ec4eb4207c9fb21121d9278a5099.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2c2986ecd7f649e9cb88a6b3108547ccee95faef38c923765a00009d6e7dcbe"

  strings:
    $s1  = "return sKnTrfy[0] + sKnTrfy[2] + sKnTrfy[4] + \".F\" + sKnTrfy[7] + sKnTrfy[9] + sKnTrfy[12] + sKnTrfy[14];" fullword ascii
    $s2  = "var zp = true  , mvQC = PRA[7] + PRA[9] + PRA[11];" fullword ascii
    $s3  = "var sKnTrfy = zTNyt(EpoYLkiKBz+\" \"+\"System Vc NswZx Obj uDCwgQ ect wgKKtvg HlBSK\", \" \");" fullword ascii
    $s4  = "Rdiz.open(HHFFc,EuNMi,false);" fullword ascii
    $s5  = "var PRA = (\"2.XMLHTTP yYcnxQW ZUMCC XML ream St DdHRNfdr AD mIYWieP O FPHx D\").split(\" \");" fullword ascii
    $s6  = "if(m>=K.length) {break;}" fullword ascii
    $s7  = "function viXQ(IRHDH,AVbqq) {" fullword ascii
    $s8  = "function EbZkEGKy(hCms) {" fullword ascii
    $s9  = "function FFGp(pnZnm,EuNMi,HHFFc) {" fullword ascii
    $s10 = "return CJJM[eLzDFW[0]];" fullword ascii
    $s11 = "function gXdWkT(AbEY,LZRzZp) {" fullword ascii
    $s12 = "if (vzgDZ == 921-721){return true;} else {return false;}" fullword ascii
    $s13 = "yxl = m; break; " fullword ascii
    $s14 = "function wycT(Jbjcn) {" fullword ascii
    $s15 = "function xqIC(DKntv) {" fullword ascii
    $s16 = "function zTNyt(Jkq,oLiZi) {" fullword ascii
    $s17 = "function FiWpS(BUUnvD) {" fullword ascii
    $s18 = "function qnlKBN(JkVkbXp) {" fullword ascii
    $s19 = "return NKugabE(Xc,dodFs[285-279]+dodFs[297-290]+dodFs[526-518]);" fullword ascii
    $s20 = "return new ActiveXObject(OmOg);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
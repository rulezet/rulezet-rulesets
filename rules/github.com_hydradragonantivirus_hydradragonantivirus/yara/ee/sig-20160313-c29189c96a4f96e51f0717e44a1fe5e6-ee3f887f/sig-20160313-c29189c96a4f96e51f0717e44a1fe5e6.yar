rule sig_20160313_c29189c96a4f96e51f0717e44a1fe5e6 {
  meta:
    description = "datamaliciousorder - file 20160313_c29189c96a4f96e51f0717e44a1fe5e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41a2fa59c7aa0f50c732c071491d3e7d8037ab08603b008da01cd62a4fb2befe"

  strings:
    $s1  = "return fOPrqYI[0] + fOPrqYI[2] + fOPrqYI[4] + \".F\" + fOPrqYI[7] + fOPrqYI[9] + fOPrqYI[12] + fOPrqYI[14];" fullword ascii
    $s2  = "var UvwXGDjv = BAGA(rNFvGGtM[463-462] + rNFvGGtM[402-399] + rNFvGGtM[962-957] + rNFvGGtM[736-730] + rNFvGGtM[349-341] + rNFvGGtM" ascii
    $s3  = "var rE = true  , ONzy = tsR[7] + tsR[9] + tsR[11];" fullword ascii
    $s4  = "var UvwXGDjv = BAGA(rNFvGGtM[463-462] + rNFvGGtM[402-399] + rNFvGGtM[962-957] + rNFvGGtM[736-730] + rNFvGGtM[349-341] + rNFvGGtM" ascii
    $s5  = "var Pzs = BAGA(ONzy + \"B.\" + tsR[5]+(518250, tsR[4]));" fullword ascii
    $s6  = "var fOPrqYI = \"Sc MkVVTKB r oOgraCxoE ipting BAoXkPb xJJ ile AuXjsVLpNIauGl System Gd SFkVw Obj LqApxn ect kBONQLV\".split(\" " ascii
    $s7  = "var tsR = (\"2.XMLHTTP QGvhZRu dreKn XML ream St HaQEPZvX AD ErzlJgy O OsLd D\").split(\" \");" fullword ascii
    $s8  = "zgGNj.open(SrENX,ExNdq,false);" fullword ascii
    $s9  = "if(C>=s.length) {break;}" fullword ascii
    $s10 = "qNY = C; break; " fullword ascii
    $s11 = "return new ActiveXObject(DGhSlp);" fullword ascii
    $s12 = "function HtXwZRPXW() {" fullword ascii
    $s13 = "function LtNPCTz(HpkH,bQTfD) {" fullword ascii
    $s14 = "function PQYqTOfu() {" fullword ascii
    $s15 = "if (iOFUD > 181758-474){return true;} else {return false;}" fullword ascii
    $s16 = "return dii.size;" fullword ascii
    $s17 = "function dMJb(NMxhr,mXIZf) {" fullword ascii
    $s18 = "return HpkH.ExpandEnvironmentStrings(bQTfD);" fullword ascii
    $s19 = "function atFi(NFqJQ) {" fullword ascii
    $s20 = "function NXuH(DbStx) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
rule sig_20160310_bf4fb0baff1be0c50118af915b80eece {
  meta:
    description = "datamaliciousorder - file 20160310_bf4fb0baff1be0c50118af915b80eece.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3e46d14c25067f3ce4fb3b952ad991eb95ea0be8c0e526be1dd6f3c2329f33e"

  strings:
    $s1  = "return IctWgVc[0] + IctWgVc[2] + IctWgVc[4] + \".F\" + IctWgVc[7] + IctWgVc[9] + IctWgVc[12] + IctWgVc[14];" fullword ascii
    $s2  = "var Un = true  , tptp = Cdq[7] + Cdq[9] + Cdq[11];" fullword ascii
    $s3  = "var Cdq = (\"2.XMLHTTP ZycpfXx RwAQm XML ream St Kquimdtx AD IMbtFPc O iVFt D\").split(\" \");" fullword ascii
    $s4  = "var IctWgVc = \"Sc pEmDuHU r iJGvmBcRw ipting uYcdwQH Jsz ile xsdUpHyqUuSNRd System mO AgcNi Obj cFkkqU ect jejNkIy\".split(\" " ascii
    $s5  = "ivGxL.open(lWjAt,wjKOi,false);" fullword ascii
    $s6  = "if(G>=W.length) {break;}" fullword ascii
    $s7  = "return cfSz.ExpandEnvironmentStrings(fILkp);" fullword ascii
    $s8  = "function xORi(IkynJ) {" fullword ascii
    $s9  = "function EoBg(ivGxL,wjKOi,lWjAt) {" fullword ascii
    $s10 = "return oBmFV.status;" fullword ascii
    $s11 = "function wotP(ecQQQ,nRAAk) {" fullword ascii
    $s12 = "return ADUVDUA(rd,dzDYz[396-390]+dzDYz[147-140]+dzDYz[258-250]);" fullword ascii
    $s13 = "function zGHZ(ilcfv) {" fullword ascii
    $s14 = "function IqperPWk(wZP) {" fullword ascii
    $s15 = "function lpUN(oBmFV) {" fullword ascii
    $s16 = "function lcRUdrn(NJBX) {" fullword ascii
    $s17 = "function CyGqP(nOoMuR) {" fullword ascii
    $s18 = "function gAYnwrlB(RnvEX,DetHSg) {" fullword ascii
    $s19 = "return wZP.size;" fullword ascii
    $s20 = "function QnUl(toOAN) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
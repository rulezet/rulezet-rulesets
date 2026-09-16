rule sig_20160310_804fcc2f53b8039f5cb46eb6d1589225 {
  meta:
    description = "datamaliciousorder - file 20160310_804fcc2f53b8039f5cb46eb6d1589225.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3412e4b6c412491522a0b6842f8eacfaca066d3fbbbbc0a60af2fc66baa531cd"

  strings:
    $s1  = "var xu = true  , Achb = Mpr[7] + Mpr[9] + Mpr[11];" fullword ascii
    $s2  = "return klfaeUK[0] + klfaeUK[2] + klfaeUK[4] + \".F\" + klfaeUK[7] + klfaeUK[9] + klfaeUK[12] + klfaeUK[14];" fullword ascii
    $s3  = "var Mpr = (\"2.XMLHTTP tiXxbTE gKoAW XML ream St ZeHmMtkH AD YnomLdM O kXYl D\").split(\" \");" fullword ascii
    $s4  = "Jtboe.open(qwNSC,TxUTQ,false);" fullword ascii
    $s5  = "var klfaeUK = \"Sc JODUKVd r NTIsPluZd ipting dzeRjom Ywh ile UZsVJevqLwfEBF System XP sCssK Obj nrVZYr ect jLDMiCS\".split(\" " ascii
    $s6  = "if(v>=u.length) {break;}" fullword ascii
    $s7  = "function tegX(bqzmz) {" fullword ascii
    $s8  = "function vgVRQ(pXmssZ) {" fullword ascii
    $s9  = "return UITW.ExpandEnvironmentStrings(yBBlM);" fullword ascii
    $s10 = "function WLtyg(uhanUx) {" fullword ascii
    $s11 = "function DsFoQBSJ(MrG) {" fullword ascii
    $s12 = "return uhanUx.position=163-163;" fullword ascii
    $s13 = "function PQgN(QAUPv) {" fullword ascii
    $s14 = "return NmJEcMc(Ov,nLuFx[342-336]+nLuFx[256-249]+nLuFx[659-651]);" fullword ascii
    $s15 = "return new ActiveXObject(pXmssZ);" fullword ascii
    $s16 = "function WMgCpSrw() {" fullword ascii
    $s17 = "if (QAUPv > 154424-177){return true;} else {return false;}" fullword ascii
    $s18 = "function kWVtBttc(KdBBO,nKSesT) {" fullword ascii
    $s19 = "tPo = v; break; " fullword ascii
    $s20 = "function COtW(QdKUM,mUlYh) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
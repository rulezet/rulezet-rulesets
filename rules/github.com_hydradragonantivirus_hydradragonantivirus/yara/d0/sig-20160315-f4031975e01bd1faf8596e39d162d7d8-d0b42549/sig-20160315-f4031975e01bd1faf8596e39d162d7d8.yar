rule sig_20160315_f4031975e01bd1faf8596e39d162d7d8 {
  meta:
    description = "datamaliciousorder - file 20160315_f4031975e01bd1faf8596e39d162d7d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18cc73c87fb96783acaade39c726e2007b9ce406c2967e77a656f3892a83dfc4"

  strings:
    $s1  = "var Oz = true  , ppdH = phd[7] + phd[9] + phd[11];" fullword ascii
    $s2  = "return NugJFYb[0] + NugJFYb[2] + NugJFYb[4] + \".F\" + NugJFYb[7] + NugJFYb[9] + NugJFYb[12] + NugJFYb[14];" fullword ascii
    $s3  = "var phd = (\"2.XMLHTTP nbHTgQd GHkeW XML ream St YFCDnIyZ AD WLsAtau O QjGM D\").split(\" \");" fullword ascii
    $s4  = "var NugJFYb = AoLgl(\"Sc obQpQsX r Ieketugzn ipting vXWVABY BNu ile VzQJftufsZdPrh System ra IJgJx Obj LYvnrn ect rTQxfiH tFxsA" ascii
    $s5  = "var NugJFYb = AoLgl(\"Sc obQpQsX r Ieketugzn ipting vXWVABY BNu ile VzQJftufsZdPrh System ra IJgJx Obj LYvnrn ect rTQxfiH tFxsA" ascii
    $s6  = "jqbRZ.open(SkTcI,RJSkQ,false);" fullword ascii
    $s7  = "function EaOS(FHBdI,uBfjF) {" fullword ascii
    $s8  = "function svKxX(mFGlDY) {" fullword ascii
    $s9  = "function iPxt(GpIbr) {" fullword ascii
    $s10 = "function YQAVkxc(WJjP,ijKtt) {" fullword ascii
    $s11 = "if(R>=I.length) {break;}" fullword ascii
    $s12 = "function QitJ(jqbRZ,RJSkQ,SkTcI) {" fullword ascii
    $s13 = "return WJjP.ExpandEnvironmentStrings(ijKtt);" fullword ascii
    $s14 = "function Kslg(prARM) {" fullword ascii
    $s15 = "return YQAVkxc(Qv,wlAFm[283-277]+wlAFm[615-608]+wlAFm[180-172]);" fullword ascii
    $s16 = "return mXwdC.status;" fullword ascii
    $s17 = "function pVBk(vmppT) {" fullword ascii
    $s18 = "function Cysd(mXwdC) {" fullword ascii
    $s19 = "function JzZX(BAGXD) {" fullword ascii
    $s20 = "return xbAzW;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
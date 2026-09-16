rule sig_20160405_fbc4244e998a95a8eafa02e80e2fa12d {
  meta:
    description = "datamaliciousorder - file 20160405_fbc4244e998a95a8eafa02e80e2fa12d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df52b8c89225fd613d2111d89ec23d86cffcee2e2f215201924d029100fdbb36"

  strings:
    $s1  = "var Tb = true  , nDFt = KNd[7] + KNd[9] + KNd[11];" fullword ascii
    $s2  = "return EhmbSmW[0] + EhmbSmW[2] + EhmbSmW[4] + \".F\" + EhmbSmW[7] + EhmbSmW[9] + EhmbSmW[12] + EhmbSmW[14];" fullword ascii
    $s3  = "var KNd = (\"2.XMLHTTP IUhSYpJ XXOwD XML ream St OspSYalZ AD SXwOGbH O dBSA D\").split(\" \");" fullword ascii
    $s4  = "wmij.open(jaGJz,JtvJU,false);" fullword ascii
    $s5  = "return EzfS;" fullword ascii
    $s6  = "function AWEX(fCmzg) {" fullword ascii
    $s7  = "function eLPvmGA(wCXI,aaOcC) {" fullword ascii
    $s8  = "if (aokiN > 179032-639){return true;} else {return false;}" fullword ascii
    $s9  = "var KOFujbc = \"irTifO*Qis*pt.S\"+\"hell*RrjFSFw*Scri*\";" fullword ascii
    $s10 = "aks = W; break; " fullword ascii
    $s11 = "return eLPvmGA(IJ,cLFyQ[537-531]+cLFyQ[544-537]+cLFyQ[458-450]);" fullword ascii
    $s12 = "return jyMBKYs;" fullword ascii
    $s13 = "function VYdx(FLoxp,JtvJU,jaGJz) {" fullword ascii
    $s14 = "function hjYefZKuA(kZAkgBNqTjH) {" fullword ascii
    $s15 = "function Dijs(GuqMB) {" fullword ascii
    $s16 = "return rWZ.size;" fullword ascii
    $s17 = "return \"gZZtYMRNAwCYwr\";" fullword ascii
    $s18 = "function Zwre(JfuRR) {" fullword ascii
    $s19 = "function GVCj(Jlttr) {" fullword ascii
    $s20 = "function DDyh(aokiN) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
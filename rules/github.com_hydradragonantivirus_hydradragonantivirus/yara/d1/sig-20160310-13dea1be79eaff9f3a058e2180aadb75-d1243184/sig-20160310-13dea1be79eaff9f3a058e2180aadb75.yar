rule sig_20160310_13dea1be79eaff9f3a058e2180aadb75 {
  meta:
    description = "datamaliciousorder - file 20160310_13dea1be79eaff9f3a058e2180aadb75.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a3141d02e42583614f86509f3e4ec6b7ef48f084018a6bc5fb6bcd02fe52ee1"

  strings:
    $s1  = "return uKCuCjI[0] + uKCuCjI[2] + uKCuCjI[4] + \".F\" + uKCuCjI[7] + uKCuCjI[9] + uKCuCjI[12] + uKCuCjI[14];" fullword ascii
    $s2  = "var XV = true  , PoMg = xKx[7] + xKx[9] + xKx[11];" fullword ascii
    $s3  = "var uKCuCjI = \"Sc kwCBdcC r vcMBlGydj ipting BKaKlcy etU ile elmwnQWeQznRgG System uK WdSFS Obj FgQYxw ect DuBdKoM\".split(\" " ascii
    $s4  = "AJRDV.open(QtsQN,tAFff,false);" fullword ascii
    $s5  = "var xKx = (\"2.XMLHTTP YrvrKRb mjtSC XML ream St EXCJmqwy AD qlIKwAl O yGNZ D\").split(\" \");" fullword ascii
    $s6  = "function JWCVyAZn(gvGpe,zcBILX) {" fullword ascii
    $s7  = "function etQC(OOfzR,HLuVI) {" fullword ascii
    $s8  = "function GVGs(uGoWw) {" fullword ascii
    $s9  = "function EFqQh(QYmfoq) {" fullword ascii
    $s10 = "function VscR(lbUKT) {" fullword ascii
    $s11 = "function LRpWPPUY() {" fullword ascii
    $s12 = "function AYeBiThdH(JGdgHZXnIsy) {" fullword ascii
    $s13 = "return new ActiveXObject(sFXUPK);" fullword ascii
    $s14 = "if (x >= uGoWw.length) {break;}" fullword ascii
    $s15 = "return VXByzBV" fullword ascii
    $s16 = "function wucNgBo(CGNT,CWUry) {" fullword ascii
    $s17 = "function XWYKx(sFXUPK) {" fullword ascii
    $s18 = "lbm = C; break; " fullword ascii
    $s19 = "return wucNgBo(WM,nujAk[927-921]+nujAk[489-482]+nujAk[200-192]);" fullword ascii
    $s20 = "function zQUS(JNuNO) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
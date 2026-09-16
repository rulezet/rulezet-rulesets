rule sig_20160322_dfaccedfb6e522dd56bedd0cfba96181 {
  meta:
    description = "datamaliciousorder - file 20160322_dfaccedfb6e522dd56bedd0cfba96181.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "171fb85642e210d3f6e823de6039bbbe04b88ccee7c57d9393f6b6d8b16dfac7"

  strings:
    $s1  = "return WScript.CreateObject(shtnn);" fullword ascii
    $s2  = "return FUVYCHg[0] + FUVYCHg[2] + FUVYCHg[4] + \".F\" + FUVYCHg[7] + FUVYCHg[9] + FUVYCHg[12] + FUVYCHg[14];" fullword ascii
    $s3  = "var Yr = true  , gZCb = Zdt[7] + Zdt[9] + Zdt[11];" fullword ascii
    $s4  = "var Zdt = (\"2.XMLHTTP cuxPKhS zbiCB XML ream St jlqTKvgr AD CsjDAZm O jyZQ D\").split(\" \");" fullword ascii
    $s5  = "RdFj.open(nETQh,gzAfQ,false);" fullword ascii
    $s6  = "var FUVYCHg = KMEhK(gfILxahlnO+\" \"+\"System bJ ZBkRX Obj QqWaKx ect zVyIRtd dkGQu\", \" \");" fullword ascii
    $s7  = "function Cofr(zTCNP) {" fullword ascii
    $s8  = "function hKLAg(yYUmwM) {" fullword ascii
    $s9  = "return IcNjbX.position=958-958;" fullword ascii
    $s10 = "return gcb.size;" fullword ascii
    $s11 = "function KMEhK(puX,VCwJI) {" fullword ascii
    $s12 = "return RWZp[QVdobh[0]];" fullword ascii
    $s13 = "return qOFQ.ExpandEnvironmentStrings(CvZXA);" fullword ascii
    $s14 = "return KgBxClc(sz,jreFl[180-174]+jreFl[559-552]+jreFl[310-302]);" fullword ascii
    $s15 = "function DpLULDApE(LNzVZaMOAJA) {" fullword ascii
    $s16 = "function ieWQ(shtnn) {" fullword ascii
    $s17 = "function SwremJFA(gcb) {" fullword ascii
    $s18 = "if (y >= OwoqO.length) {break;}" fullword ascii
    $s19 = "function yMyC(CuYvI) {" fullword ascii
    $s20 = "if(V>=T.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
rule sig_20160405_e04703e989792e76aa73e70046697c02 {
  meta:
    description = "datamaliciousorder - file 20160405_e04703e989792e76aa73e70046697c02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f3cde6ff722e900034f483fd9bfa75a410bb0c1d8f81f998e68d512f06bd252"

  strings:
    $s1  = "var mB = true  , YlRU = Nvw[7] + Nvw[9] + Nvw[11];" fullword ascii
    $s2  = "return cLJiUFY[0] + cLJiUFY[2] + cLJiUFY[4] + \".F\" + cLJiUFY[7] + cLJiUFY[9] + cLJiUFY[12] + cLJiUFY[14];" fullword ascii
    $s3  = "Ogph.open(dpqKi,aZAPY,false);" fullword ascii
    $s4  = "var Nvw = (\"2.XMLHTTP gwCNhrU TZWxT XML ream St ZpwrYDeG AD XRcdiDo O RSPu D\").split(\" \");" fullword ascii
    $s5  = "if(X>=a.length) {break;}" fullword ascii
    $s6  = "var aGHdQYr = \"OjDdBP*OSs*pt.S\"+\"hell*UQPapjc*Scri*\";" fullword ascii
    $s7  = "function rPFW(SwjrG) {" fullword ascii
    $s8  = "function XDiCeyMI(eCNP) {" fullword ascii
    $s9  = "if (Z >= npsdN.length) {break;}" fullword ascii
    $s10 = "function FtAwB(QfLhCj) {" fullword ascii
    $s11 = "function lBac(WwHDC) {" fullword ascii
    $s12 = "function GpuUWa(fElExfB) {" fullword ascii
    $s13 = "function gBXzVuL(OeDG,vzpat) {" fullword ascii
    $s14 = "return xzcn;" fullword ascii
    $s15 = "function XFhC(hJyvB) {" fullword ascii
    $s16 = "function nLAM(ABRnf,jDKxB) {" fullword ascii
    $s17 = "function gHqq(DPAsH,wpalC) {" fullword ascii
    $s18 = "function yUYfMOjUW(UHwLpAKXzzG) {" fullword ascii
    $s19 = "function nNaaeYi(dhnw) {" fullword ascii
    $s20 = "return NBVNwBS;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
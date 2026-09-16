rule sig_20160301_358f821a4c56357f045080964be1eb5d {
  meta:
    description = "datamaliciousorder - file 20160301_358f821a4c56357f045080964be1eb5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e2444fdf365024ff5aab0cecaef6451af8f8dd7218e6bb95bdfe0c2eb50b21f"

  strings:
    $s1  = "var Pg = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(WYkwS);" fullword ascii
    $s3  = "return \"Sc\" + \"r\" + yUOkBRq + \".F\" + VwqebpdRxb + UuFnI + \"Obj\" + \"ect\";" fullword ascii
    $s4  = "var rj = true  , iPlr = GbI[7] + \"\" + GbI[9];" fullword ascii
    $s5  = "var GbI = (HTF + \"TTP\" + \" gYmbxPv KBWsO XML ream St gKhTIFyE AD wQUjjGw OD\").split(\" \");" fullword ascii
    $s6  = "yZEhi.open(DgbTq,vrvLl,false);" fullword ascii
    $s7  = "function MkBu(aIfBX,dtGxD) {" fullword ascii
    $s8  = "function coXBuHFnx(rZRjdvEbzxR) {" fullword ascii
    $s9  = "return IJ.ExpandEnvironmentStrings(Pg);" fullword ascii
    $s10 = "function kZjgK(pbrzJW) {" fullword ascii
    $s11 = "function pSQV(CNJbD,RnVJo) {" fullword ascii
    $s12 = "return AIFKx;" fullword ascii
    $s13 = "if(P>=p.length) {break;}" fullword ascii
    $s14 = "function agzJ(yZEhi,vrvLl,DgbTq) {" fullword ascii
    $s15 = "function JbAp(xkwhK) {" fullword ascii
    $s16 = "ZTR = P; break; " fullword ascii
    $s17 = "return ArPpS.status;" fullword ascii
    $s18 = "function sUsM(WYkwS) {" fullword ascii
    $s19 = "function HsXS(OHRcc) {" fullword ascii
    $s20 = "function lCuV(rZTzl) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
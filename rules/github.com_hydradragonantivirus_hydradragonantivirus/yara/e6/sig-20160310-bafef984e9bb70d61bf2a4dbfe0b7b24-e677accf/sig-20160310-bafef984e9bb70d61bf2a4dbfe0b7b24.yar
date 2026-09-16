rule sig_20160310_bafef984e9bb70d61bf2a4dbfe0b7b24 {
  meta:
    description = "datamaliciousorder - file 20160310_bafef984e9bb70d61bf2a4dbfe0b7b24.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d86514eb813b2b991892db12c0b307847aed4e243224ac69efe6afc3842da472"

  strings:
    $s1  = "var Uc = true  , rMay = LJP[7] + LJP[9] + LJP[11];" fullword ascii
    $s2  = "return zIYmzee[0] + zIYmzee[2] + zIYmzee[4] + \".F\" + zIYmzee[7] + zIYmzee[9] + zIYmzee[12] + zIYmzee[14];" fullword ascii
    $s3  = "var LJP = (\"2.XMLHTTP RCgFXRX dqCeB XML ream St rcuXfRnP AD BFjHxKN O ertN D\").split(\" \");" fullword ascii
    $s4  = "var zIYmzee = \"Sc ktnRnGV r GmnIoUmBO ipting dwaxknc PcS ile UrfABcyEHoBtzk System Wm iBLKb Obj MEwsXt ect ZENUylQ\".split(\" " ascii
    $s5  = "LsVhr.open(TBXqS,WQoHu,false);" fullword ascii
    $s6  = "return oio.size;" fullword ascii
    $s7  = "if (B >= AXgvG.length) {break;}" fullword ascii
    $s8  = "function fQKV(hiMnT) {" fullword ascii
    $s9  = "KRk = F; break; " fullword ascii
    $s10 = "if(F>=x.length) {break;}" fullword ascii
    $s11 = "function FniWJauLk(hgoCM,gOFNa,HKINh,UtGP) {" fullword ascii
    $s12 = "function dKty(LsVhr,WQoHu,TBXqS) {" fullword ascii
    $s13 = "function TiIp(TBqlD,ycLXq) {" fullword ascii
    $s14 = "return olRkgWw(TY,OxxUl[567-561]+OxxUl[853-846]+OxxUl[246-238]);" fullword ascii
    $s15 = "function CbxG(qpFtn) {" fullword ascii
    $s16 = "function wHrY(cKdTL) {" fullword ascii
    $s17 = "function nzkDqbd(DlxT) {" fullword ascii
    $s18 = "return jifNEj.position=861-861;" fullword ascii
    $s19 = "function olRkgWw(QGEk,qtQQW) {" fullword ascii
    $s20 = "function oaSgC(jifNEj) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
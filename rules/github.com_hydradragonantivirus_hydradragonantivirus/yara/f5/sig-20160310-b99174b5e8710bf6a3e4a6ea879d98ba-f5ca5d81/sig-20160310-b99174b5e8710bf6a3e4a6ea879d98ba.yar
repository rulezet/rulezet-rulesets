rule sig_20160310_b99174b5e8710bf6a3e4a6ea879d98ba {
  meta:
    description = "datamaliciousorder - file 20160310_b99174b5e8710bf6a3e4a6ea879d98ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b952a631ed5f4d452039a05bbc6b4233d47895d6ebfbd6ce41ea334fbd0ff836"

  strings:
    $s1  = "return wUZKwKe[0] + wUZKwKe[2] + wUZKwKe[4] + \".F\" + wUZKwKe[7] + wUZKwKe[9] + wUZKwKe[12] + wUZKwKe[14];" fullword ascii
    $s2  = "var bk = true  , Kmbi = zBf[7] + zBf[9] + zBf[11];" fullword ascii
    $s3  = "var zBf = (\"2.XMLHTTP EcGPQZP IEtDa XML ream St OzaEBXHd AD RDmffoX O JzJX D\").split(\" \");" fullword ascii
    $s4  = "var wUZKwKe = \"Sc kTtZuQN r KaDuntfIj ipting CYMaQSP JMI ile vKJieiWmeaXcbP System ux EmtFT Obj LhZErj ect wQtRSpM\".split(\" " ascii
    $s5  = "SSadh.open(tCxhr,kmDKr,false);" fullword ascii
    $s6  = "if(y>=p.length) {break;}" fullword ascii
    $s7  = "function cSxiaxkj(GzJai,cJHsBx) {" fullword ascii
    $s8  = "function qyFS(wyAio) {" fullword ascii
    $s9  = "function vkMiRnpN(KaV) {" fullword ascii
    $s10 = "function TPtC(RwZhl,imqwR) {" fullword ascii
    $s11 = "if (jhjEi == 515-315){return true;} else {return false;}" fullword ascii
    $s12 = "vNg = y; break; " fullword ascii
    $s13 = "function kjuD(uqITf) {" fullword ascii
    $s14 = "return xAkF.responseBody;" fullword ascii
    $s15 = "function utIltSK(xAkF) {" fullword ascii
    $s16 = "function SHut(CQSGK,dxlBZ) {" fullword ascii
    $s17 = "function ooBlTWSg() {" fullword ascii
    $s18 = "return SeFpu;" fullword ascii
    $s19 = "function lrrV(SdKqN) {" fullword ascii
    $s20 = "function vpKm(dwCXZ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
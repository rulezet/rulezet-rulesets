rule sig_20160323_fa0303282a18aa1ec78eebea648424f6 {
  meta:
    description = "datamaliciousorder - file 20160323_fa0303282a18aa1ec78eebea648424f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8179b98099762ae85067730080d9dc0fd4e48999c128dbe6b5d184f1d0283519"

  strings:
    $s1  = "return WScript.CreateObject(Pvjya);" fullword ascii
    $s2  = "return ZsPY[eiuDqb[0]];" fullword ascii
    $s3  = "function pJEHEOF(ZsPY) {" fullword ascii
    $s4  = "var gy = true  , qhJc = hxq[7] + hxq[9] + hxq[11];" fullword ascii
    $s5  = "return OuBttgU[0] + OuBttgU[2] + OuBttgU[4] + \".F\" + OuBttgU[7] + OuBttgU[9] + OuBttgU[12] + OuBttgU[14];" fullword ascii
    $s6  = "var hxq = (\"2.XMLHTTP vsgkEAy mRlaN XML ream St VSSKWmLl AD WQKRDkH O iTet D\").split(\" \");" fullword ascii
    $s7  = "osnr.open(dKhGN,zmMif,false);" fullword ascii
    $s8  = "var OuBttgU = aBNLy(toSaepHUdb+\" \"+\"System jK kkiIO Obj IwdxoB ect WKHtxaI mPUSV\", \" \");" fullword ascii
    $s9  = "function ffWSw(neqYhe) {" fullword ascii
    $s10 = "function eySKedkqP(AEebsOBblkf) {" fullword ascii
    $s11 = "MHs = W; break; " fullword ascii
    $s12 = "function VlmN(Pvjya) {" fullword ascii
    $s13 = "return vjDYN.status;" fullword ascii
    $s14 = "function LSxJ(lxktV) {" fullword ascii
    $s15 = "function vbjz(pWBQw) {" fullword ascii
    $s16 = "function KvyT(ZJWLP) {" fullword ascii
    $s17 = "return VlGTaWH(ZQ,lotbt[382-376]+lotbt[174-167]+lotbt[889-881]);" fullword ascii
    $s18 = "return ipG.split(NzlQg);" fullword ascii
    $s19 = "function IbjGXkQqT(woSkY) {" fullword ascii
    $s20 = "function VlGTaWH(hjJW,uypOv) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
rule sig_20160411_6a24636656a550daea7943408ef82966 {
  meta:
    description = "datamaliciousorder - file 20160411_6a24636656a550daea7943408ef82966.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0897e0e1d980a70bf36b1bf8a8204261a130c32b12ba396c84dd7b52e71ab7d4"

  strings:
    $s1  = "var GH = true  , cCgN = SKw[7] + SKw[9] + SKw[11];" fullword ascii
    $s2  = "return UlxRMFT[0] + UlxRMFT[2] + UlxRMFT[4] + \".F\" + UlxRMFT[7] + UlxRMFT[9] + UlxRMFT[12] + UlxRMFT[14];" fullword ascii
    $s3  = "KTnj.open(xfDrP,Bitjz,false);" fullword ascii
    $s4  = "var SKw = (\"2.XMLHTTP NcFnefB JDyhg XML ream St gjxKgENd AD cPyawFF O dDUx D\").split(\" \");" fullword ascii
    $s5  = "if(L>=u.length) {break;}" fullword ascii
    $s6  = "function DUTC(KjVLA) {" fullword ascii
    $s7  = "return KvaKLfc[0];" fullword ascii
    $s8  = "return RHVIpLg(Jo,RyAvzU+Lzoab[745-737]);" fullword ascii
    $s9  = "if (nqEQN == 1176-976){return true;} else {return false;}" fullword ascii
    $s10 = "function ZXvgI(MUv,dPZlJ) {" fullword ascii
    $s11 = "function lUIit(HxWWDyCC,Bpxi) {" fullword ascii
    $s12 = "function iZBo(snttq) {" fullword ascii
    $s13 = "function GjxG(nqEQN) {" fullword ascii
    $s14 = "function bUDy(hbYhx,aMnDD) {" fullword ascii
    $s15 = "function huzD(EbgAs,Bitjz,xfDrP) {" fullword ascii
    $s16 = "function mrnv(fdUcS) {" fullword ascii
    $s17 = "if (J >= aAzDu.length) {break;}" fullword ascii
    $s18 = "return hlPGae[TBch[221-221]]=893-893;" fullword ascii
    $s19 = "return ILpahqd;" fullword ascii
    $s20 = "function bgVwi(hlPGae) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
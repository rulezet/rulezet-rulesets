rule sig_20160404_c2f56d4db5cf79d52ecc8f5df75636a3 {
  meta:
    description = "datamaliciousorder - file 20160404_c2f56d4db5cf79d52ecc8f5df75636a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a64d97ceae6e48b78c09fb46141290c72b38afa9b08c0222bcabbe9096691a2"

  strings:
    $s1  = "function dLll(tcDPL) {" fullword ascii
    $s2  = "return pTicGpf[0] + pTicGpf[2] + pTicGpf[4] + \".F\" + pTicGpf[7] + pTicGpf[9] + pTicGpf[12] + pTicGpf[14];" fullword ascii
    $s3  = "var Yr = true  , nYrj = jwW[7] + jwW[9] + jwW[11];" fullword ascii
    $s4  = "var jwW = (\"2.XMLHTTP yuOloEG acSsw XML ream St VJiNnWSv AD PdQNkUw O yBhQ D\").split(\" \");" fullword ascii
    $s5  = "BgTx.open(kSGfI,txhoh,false);" fullword ascii
    $s6  = "var pTicGpf = wOiKA(ArJMibPPgO+\" \"+\"System jx pXFZW Obj UNKype ect kezOdhs jizyc\", \" \");" fullword ascii
    $s7  = "var ndnxrCU = \"RTnXSS*WBT*pt.S\"+\"hell*WjKtZQp*Scri*\";" fullword ascii
    $s8  = "function sOTm(KxRyL) {" fullword ascii
    $s9  = "function mcKOq(xnkQzE) {" fullword ascii
    $s10 = "function wrrQJwJ(tOjA) {" fullword ascii
    $s11 = "function RjlUbm(YzCL,dlJGRv) {" fullword ascii
    $s12 = "function dPMAJnAyG(VQhDlIWvqxF) {" fullword ascii
    $s13 = "return boWxkss(pZ,GOrlB[310-304]+GOrlB[670-663]+GOrlB[607-599]);" fullword ascii
    $s14 = "function OGGzGGilL(nMbEf) {" fullword ascii
    $s15 = "function dCEt(QmFrT,TpMJo) {" fullword ascii
    $s16 = "return UWdiuJB;" fullword ascii
    $s17 = "return zMf.size;" fullword ascii
    $s18 = "function UCld(rDREH,YHMkU) {" fullword ascii
    $s19 = "return tOjA[yxbOSi[0]];" fullword ascii
    $s20 = "return new ActiveXObject(Kqik);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
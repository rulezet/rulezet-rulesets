rule sig_20160404_9fb203da612848eb27efa175d767060f {
  meta:
    description = "datamaliciousorder - file 20160404_9fb203da612848eb27efa175d767060f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a48875bf90d9f496fe8fa4a5af0ad673263dc075efe6f0ae06999d851817668d"

  strings:
    $s1  = "return ZxSgdQB[0] + ZxSgdQB[2] + ZxSgdQB[4] + \".F\" + ZxSgdQB[7] + ZxSgdQB[9] + ZxSgdQB[12] + ZxSgdQB[14];" fullword ascii
    $s2  = "var BB = true  , uAEd = Kat[7] + Kat[9] + Kat[11];" fullword ascii
    $s3  = "var ZxSgdQB = adUCg(XiedykGpvv+\" \"+\"System bu pUCJh Obj qnjkZW ect soLcHMA MRrmo\", \" \");" fullword ascii
    $s4  = "var Kat = (\"2.XMLHTTP jxRsrnZ KCuYE XML ream St qaIVZJgJ AD xkPzDOI O sjKI D\").split(\" \");" fullword ascii
    $s5  = "AwbN.open(NZExK,ypHZY,false);" fullword ascii
    $s6  = "if(F>=c.length) {break;}" fullword ascii
    $s7  = "function TdWO(agWbv) {" fullword ascii
    $s8  = "return TvagIdq(MX,LcRpD[706-700]+LcRpD[839-832]+LcRpD[320-312]);" fullword ascii
    $s9  = "function KPhh(zyMPr,zsbdW) {" fullword ascii
    $s10 = "ouM = F; break; " fullword ascii
    $s11 = "return tGw.split(hENGU);" fullword ascii
    $s12 = "function YXrQut(qnnU,bqFiTZ) {" fullword ascii
    $s13 = "return oPpD[rxeKev[0]];" fullword ascii
    $s14 = "function gDgZ(JJpKc) {" fullword ascii
    $s15 = "return PLUgD.status;" fullword ascii
    $s16 = "return DfWVzaL;" fullword ascii
    $s17 = "function dAEl(dzazx,nmdRb) {" fullword ascii
    $s18 = "function WAYl(MCKVM) {" fullword ascii
    $s19 = "function bshe(eHNsp) {" fullword ascii
    $s20 = "return new ActiveXObject(ShqI);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
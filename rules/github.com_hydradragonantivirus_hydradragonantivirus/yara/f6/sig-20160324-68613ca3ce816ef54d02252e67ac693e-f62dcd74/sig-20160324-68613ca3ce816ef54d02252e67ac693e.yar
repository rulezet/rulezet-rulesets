rule sig_20160324_68613ca3ce816ef54d02252e67ac693e {
  meta:
    description = "datamaliciousorder - file 20160324_68613ca3ce816ef54d02252e67ac693e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e90aef6d9a3122d6a285e133b38d0521db9118266cab506232e5fc129a3d89dd"

  strings:
    $s1  = "return WScript.CreateObject(gHvxM);" fullword ascii
    $s2  = "var KZ = true  , mMjs = dyN[7] + dyN[9] + dyN[11];" fullword ascii
    $s3  = "return vLZgQmO[0] + vLZgQmO[2] + vLZgQmO[4] + \".F\" + vLZgQmO[7] + vLZgQmO[9] + vLZgQmO[12] + vLZgQmO[14];" fullword ascii
    $s4  = "var vLZgQmO = BOUhw(pmzekcUNCJ+\" \"+\"System Vc OaYNL Obj pyaAcS ect lZHvQyh NXdcu\", \" \");" fullword ascii
    $s5  = "var dyN = (\"2.XMLHTTP LCqwZHY bBuff XML ream St WPMbuAep AD JNsXNGB O NZOY D\").split(\" \");" fullword ascii
    $s6  = "FpUn.open(sVyhz,jQPHP,false);" fullword ascii
    $s7  = "function PJRw(uXztb) {" fullword ascii
    $s8  = "function YtskDtUL(Yfko) {" fullword ascii
    $s9  = "return tPOn[zIzBCk[0]];" fullword ascii
    $s10 = "function EwPHNQD(tPOn) {" fullword ascii
    $s11 = "function iwDO(NVORh) {" fullword ascii
    $s12 = "return ahltBhh(sd,Chwpi[818-812]+Chwpi[115-108]+Chwpi[182-174]);" fullword ascii
    $s13 = "if(c>=s.length) {break;}" fullword ascii
    $s14 = "function srkUqetU(sbR) {" fullword ascii
    $s15 = "return fGwNM.status;" fullword ascii
    $s16 = "var vLxxdyC = \"OZqfdX*YCw*pt.S\"+\"hell*MiWXVfh*Scri*\";" fullword ascii
    $s17 = "function nNHFs(YzESfs) {" fullword ascii
    $s18 = "return sbR.size;" fullword ascii
    $s19 = "function GIQDkywfm(APSJY) {" fullword ascii
    $s20 = "return dyvH.ExpandEnvironmentStrings(OjZWs);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
rule sig_20160405_cedf910e1678ca76fa80d0aba6bc9a05 {
  meta:
    description = "datamaliciousorder - file 20160405_cedf910e1678ca76fa80d0aba6bc9a05.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32027e5b8e0d821bcc5f791d741670c5c5507ede6f753c7e483e2fab3308f0b0"

  strings:
    $s1  = "return WVVGqvV[0] + WVVGqvV[2] + WVVGqvV[4] + \".F\" + WVVGqvV[7] + WVVGqvV[9] + WVVGqvV[12] + WVVGqvV[14];" fullword ascii
    $s2  = "var uz = true  , tvvM = vLh[7] + vLh[9] + vLh[11];" fullword ascii
    $s3  = "var vLh = (\"2.XMLHTTP yHQzKpx ZolXS XML ream St TeORlfGC AD XGZRUzr O AIeQ D\").split(\" \");" fullword ascii
    $s4  = "eIwN.open(lhKMO,zKmpR,false);" fullword ascii
    $s5  = "if(O>=i.length) {break;}" fullword ascii
    $s6  = "function cUuxY(LWygojHx,Oegc) {" fullword ascii
    $s7  = "return new ActiveXObject(CXUF);" fullword ascii
    $s8  = "function SKJnzWwhI(XRSEP) {" fullword ascii
    $s9  = "if (rUUJY > 155267-888){return true;} else {return false;}" fullword ascii
    $s10 = "function gYBz(rUUJY) {" fullword ascii
    $s11 = "function hugv(AzVHQ,Odeta) {" fullword ascii
    $s12 = "function cNSoaWn(faJV,Mossz) {" fullword ascii
    $s13 = "return mQM.size;" fullword ascii
    $s14 = "Xje = O; break; " fullword ascii
    $s15 = "return IpGjr.status;" fullword ascii
    $s16 = "function QJxD(TUNuV) {" fullword ascii
    $s17 = "function LsSo(CKfuv) {" fullword ascii
    $s18 = "if (sILpN == 516-316){return true;} else {return false;}" fullword ascii
    $s19 = "return cNSoaWn(CE,glAXk[519-513]+glAXk[995-988]+glAXk[847-839]);" fullword ascii
    $s20 = "return KsBqyyJ[0];" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
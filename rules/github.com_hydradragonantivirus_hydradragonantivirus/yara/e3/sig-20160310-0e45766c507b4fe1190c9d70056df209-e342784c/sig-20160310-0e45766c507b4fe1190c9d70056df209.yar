rule sig_20160310_0e45766c507b4fe1190c9d70056df209 {
  meta:
    description = "datamaliciousorder - file 20160310_0e45766c507b4fe1190c9d70056df209.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3deee72a9f440ed317724a4df3e09bbf06a82128e13686c5f6db1f3807cfe2db"

  strings:
    $s1  = "return osENOnd[0] + osENOnd[2] + osENOnd[4] + \".F\" + osENOnd[7] + osENOnd[9] + osENOnd[12] + osENOnd[14];" fullword ascii
    $s2  = "var LE = true  , uSWx = CCE[7] + CCE[9] + CCE[11];" fullword ascii
    $s3  = "var osENOnd = \"Sc GekaOoQ r woVYaNfqv ipting PyQHqkS mUw ile gzxHAehddaeGwU System nr zDcUW Obj pGuihb ect FIfNYUA\".split(\" " ascii
    $s4  = "var CCE = (\"2.XMLHTTP KGOQOsw JiJSC XML ream St YGypyXrU AD gaeUcCy O QYSU D\").split(\" \");" fullword ascii
    $s5  = "WNoHD.open(YILdb,eqQug,false);" fullword ascii
    $s6  = "function gawy(dKvWD) {" fullword ascii
    $s7  = "function YSfFk(gIdySU) {" fullword ascii
    $s8  = "return bePi.responseBody;" fullword ascii
    $s9  = "if (EKLWe > 170428-211){return true;} else {return false;}" fullword ascii
    $s10 = "function TwuR(vMAwn) {" fullword ascii
    $s11 = "function IRvVVjEDj(ydYOAZBpxpT) {" fullword ascii
    $s12 = "return new ActiveXObject(HrscfU);" fullword ascii
    $s13 = "Xxy = O; break; " fullword ascii
    $s14 = "function dBvRgUq(bePi) {" fullword ascii
    $s15 = "function pMNNBsJaS(oUvqR,zZdJr,bLFSJ,lzYI) {" fullword ascii
    $s16 = "return HWgYKyE" fullword ascii
    $s17 = "return kioEgtI(dD,Fnypi[693-687]+Fnypi[298-291]+Fnypi[405-397]);" fullword ascii
    $s18 = "return dKvWD.status;" fullword ascii
    $s19 = "function PYed(mRQHa) {" fullword ascii
    $s20 = "function GKSs(XsDgg) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
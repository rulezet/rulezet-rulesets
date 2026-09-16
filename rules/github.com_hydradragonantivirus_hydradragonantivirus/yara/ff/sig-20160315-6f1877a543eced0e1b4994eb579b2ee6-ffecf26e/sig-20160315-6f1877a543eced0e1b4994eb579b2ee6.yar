rule sig_20160315_6f1877a543eced0e1b4994eb579b2ee6 {
  meta:
    description = "datamaliciousorder - file 20160315_6f1877a543eced0e1b4994eb579b2ee6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3aafc8b05545e5d5a1f940ec05df7dcf530d97c83fb505e3e47957536fde592e"

  strings:
    $s1  = "return kWTRIJU[0] + kWTRIJU[2] + kWTRIJU[4] + \".F\" + kWTRIJU[7] + kWTRIJU[9] + kWTRIJU[12] + kWTRIJU[14];" fullword ascii
    $s2  = "var ab = true  , ySDo = YTx[7] + YTx[9] + YTx[11];" fullword ascii
    $s3  = "var YTx = (\"2.XMLHTTP XlJRsSE KWKgG XML ream St gjcRmmOV AD PdOzXgx O WvAi D\").split(\" \");" fullword ascii
    $s4  = "var kWTRIJU = SfSNc(\"Sc PTeWVYH r lRmSolhuA ipting tfFsXqV hzu ile oiBiBuTNNJsVVX System bd uRwSM Obj pdTEpq ect YMqkjCL cGATO" ascii
    $s5  = "var kWTRIJU = SfSNc(\"Sc PTeWVYH r lRmSolhuA ipting tfFsXqV hzu ile oiBiBuTNNJsVVX System bd uRwSM Obj pdTEpq ect YMqkjCL cGATO" ascii
    $s6  = "KaRxy.open(mdOuL,kgbfp,false);" fullword ascii
    $s7  = "function zNDcl(IWvuSF) {" fullword ascii
    $s8  = "function IrjoSaOtL(xHfsj) {" fullword ascii
    $s9  = "function BmqT(nxLjn) {" fullword ascii
    $s10 = "function VVHN(hEdVI,jNTQh) {" fullword ascii
    $s11 = "function gSxfiov(crsG,rRAyA) {" fullword ascii
    $s12 = "function QYlo(wsVtK) {" fullword ascii
    $s13 = "function xKSF(xfKYr) {" fullword ascii
    $s14 = "function zykB(RKtux,rwNdz) {" fullword ascii
    $s15 = "if (nxLjn == 996-796){return true;} else {return false;}" fullword ascii
    $s16 = "function YMUa(swhbc) {" fullword ascii
    $s17 = "return gSxfiov(yv,zaMRJ[195-189]+zaMRJ[136-129]+zaMRJ[131-123]);" fullword ascii
    $s18 = "return new ActiveXObject(IWvuSF);" fullword ascii
    $s19 = "return ZByn.responseBody;" fullword ascii
    $s20 = "if (d >= MerAr.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
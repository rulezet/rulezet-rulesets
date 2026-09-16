rule sig_20160301_0e8ad2586aeeea42a40966c77587f71e {
  meta:
    description = "datamaliciousorder - file 20160301_0e8ad2586aeeea42a40966c77587f71e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ed0bc9ce7d52f5aacaa7d9c5f05f626a8bdc63d558a61f768dbe4834e7717ef"

  strings:
    $s1  = "var nr = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(HMUFX);" fullword ascii
    $s3  = "function ziRbzxCNX(GSSbY,getfl,hOMyj) {" fullword ascii
    $s4  = "var pn = true  , ZNNC = sEN[7] + \"\" + sEN[9];" fullword ascii
    $s5  = "var sEN = (yDe + \"TTP\" + \" ZgmscWI XsIGe XML ream St evAtIIYO AD QQKczUw OD\").split(\" \");" fullword ascii
    $s6  = "return \"Sc\" + \"r\" + NdjyPwG + \".F\" + CkxtszosqR + DIEiK + \"Obj\" + \"ect\";" fullword ascii
    $s7  = "gRqDw.open(BESmJ,DMBRz,false);" fullword ascii
    $s8  = "if (QOuvp > 155490-442){return true;} else {return false;}" fullword ascii
    $s9  = "Owu = c; break; " fullword ascii
    $s10 = "function Vzqm(zuUPh) {" fullword ascii
    $s11 = "function LzwDDcPJT(FxvDUgnIWwc) {" fullword ascii
    $s12 = "function UYKv(QOuvp) {" fullword ascii
    $s13 = "function Mirr(WmZBD) {" fullword ascii
    $s14 = "function YvLo(BBYGE) {" fullword ascii
    $s15 = "function hnXm(GaHFk,AYTJW) {" fullword ascii
    $s16 = "return new ActiveXObject(jlSpvF);" fullword ascii
    $s17 = "return st.ExpandEnvironmentStrings(nr);" fullword ascii
    $s18 = "function bVvh(PofMs) {" fullword ascii
    $s19 = "return JIvmv;" fullword ascii
    $s20 = "if (((new Date())>0,7113722888)) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
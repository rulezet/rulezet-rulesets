rule sig_20160305_94c08e4debc436d391b79be784064cf4 {
  meta:
    description = "datamaliciousorder - file 20160305_94c08e4debc436d391b79be784064cf4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a41eab131a1ca28dff90c7a4b6b8612c08c74dd465e7a7ed5959fe3a18add1d8"

  strings:
    $s1  = "var WMUof = \"DwmKig LpA pt.Shell rtLRPel Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var SjC = (Zhw + \"TTP\" + \" FCHTmtD WGSGq XML ream St GUSfaNtW AD AVlDIFE OD\").split(\" \");" fullword ascii
    $s3  = "var Rb = true  , FqTT = SjC[7] + \"\" + SjC[9];" fullword ascii
    $s4  = "return KlfGKHG[0] + KlfGKHG[2] + KlfGKHG[4] + \".F\" + KlfGKHG[7] + KlfGKHG[9] + KlfGKHG[12] + KlfGKHG[14];" fullword ascii
    $s5  = "var KlfGKHG = \"Sc gGfuajC r JHQmzEYQC ipting kjuRfLp DAP ile YFPQXIDzgxBjmN System sF AfYbN Obj erXJmm ect SztpJgm\".split(\" " ascii
    $s6  = "JfAjp.open(uENYA,waIut,false);" fullword ascii
    $s7  = "function iyVxewXpk(TJvsR,XUCKR,znAmN) {" fullword ascii
    $s8  = "KiS = v; break; " fullword ascii
    $s9  = "function woOi(RHoZb) {" fullword ascii
    $s10 = "function AmDj(sLCbk,WeLaG) {" fullword ascii
    $s11 = "function xGbFzLR(jtuU) {" fullword ascii
    $s12 = "function GOplfPBG() {" fullword ascii
    $s13 = "function VEti(odXbV) {" fullword ascii
    $s14 = "function edcq(JfAjp,waIut,uENYA) {" fullword ascii
    $s15 = "if(v>=g.length) {break;}" fullword ascii
    $s16 = "function NeLBAfZar(xJrxaMrWsZz) {" fullword ascii
    $s17 = "return WU.ExpandEnvironmentStrings(WMUof[6]);" fullword ascii
    $s18 = "function mzjN(yoTpr) {" fullword ascii
    $s19 = "function DiVO(eaQcS) {" fullword ascii
    $s20 = "if (eaQcS > 169457-259){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
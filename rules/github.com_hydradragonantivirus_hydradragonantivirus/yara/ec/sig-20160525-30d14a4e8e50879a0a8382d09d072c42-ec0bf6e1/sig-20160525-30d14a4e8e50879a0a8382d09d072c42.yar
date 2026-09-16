rule sig_20160525_30d14a4e8e50879a0a8382d09d072c42 {
  meta:
    description = "datamaliciousorder - file 20160525_30d14a4e8e50879a0a8382d09d072c42.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d24a8e81a23e9f7f2d4070bf888d040c57346a2250172e3b43fd28e0942df291"

  strings:
    $s1  = "Math.cos(63), 2) - 1))-634)) EBBLPBdIQMuzBeMaXc += bJ(QRreEUKcEfAvUssqfG);else if (YamZxgkSGJ == (883 + Math.round((Math.pow(Mat" ascii
    $s2  = "function XlZeyhfxLLzTe(VUpqjgPNxTqJJ) {var UbjjKSLHzqEjNlanPFRSonZ = AOrIxAQDQzgEnwixu.join(hRkoqGlINtLRIoSg[0]);var QRreEUKcEfA" ascii
    $s3  = "function waPvrvXUxsmpbyhNnq(gLTOQuyXPYTSjVhUK,GGALleWnxKC){return gLTOQuyXPYTSjVhUK.charAt(GGALleWnxKC);}" fullword ascii
    $s4  = "pqjgPNxTqJJ.length);return EBBLPBdIQMuzBeMaXc;}" fullword ascii
    $s5  = "function NxuLxkXEwOOq(GyKrlYxuXaYAzfvIxkHt,HftQdokbeCnO){return String.fromCharCode(GyKrlYxuXaYAzfvIxkHt,HftQdokbeCnO);}" fullword ascii
    $s6  = "function CZJyo(OVkCNVb,dFHyzZwXOVfdqTrvHcDaYaEx){return OVkCNVb.indexOf(dFHyzZwXOVfdqTrvHcDaYaEx);}" fullword ascii
    $s7  = "function GEuZZljvWxx(ZdTwzPLWiWEfUaXPIu,hwTgesWECDcntwEPbuiO,RgXAL){return String.fromCharCode(ZdTwzPLWiWEfUaXPIu,hwTgesWECDcntw" ascii
    $s8  = "vruqDe);else EBBLPBdIQMuzBeMaXc += GEuZZljvWxx(QRreEUKcEfAvUssqfG, IOQwBwKhCOfwPpZbMvruqDe, PYrdek);} while (afuNWGiVuQcPEV < VU" ascii
    $s9  = "function GEuZZljvWxx(ZdTwzPLWiWEfUaXPIu,hwTgesWECDcntwEPbuiO,RgXAL){return String.fromCharCode(ZdTwzPLWiWEfUaXPIu,hwTgesWECDcntw" ascii
    $s10 = "function XlZeyhfxLLzTe(VUpqjgPNxTqJJ) {var UbjjKSLHzqEjNlanPFRSonZ = AOrIxAQDQzgEnwixu.join(hRkoqGlINtLRIoSg[0]);var QRreEUKcEfA" ascii
    $s11 = "function bJ(iyKrAgUxIXSjDv){return String.fromCharCode(iyKrAgUxIXSjDv);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
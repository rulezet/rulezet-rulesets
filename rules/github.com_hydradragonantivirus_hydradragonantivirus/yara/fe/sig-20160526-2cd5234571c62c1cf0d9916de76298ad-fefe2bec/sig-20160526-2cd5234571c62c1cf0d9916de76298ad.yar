rule sig_20160526_2cd5234571c62c1cf0d9916de76298ad {
  meta:
    description = "datamaliciousorder - file 20160526_2cd5234571c62c1cf0d9916de76298ad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f5436f2dfc89117011fbaf763bf257544d8a9d87631b53d13fa5df916034987"

  strings:
    $s1  = "pCuPlyyJZhv);else if (rSHxFVvsPJfWnRPkGzdlGJ == (588 + Math.round((Math.pow(Math.sin(71), 2) + Math.pow(Math.cos(71), 2) - 1))-5" ascii
    $s2  = "function vQRfDvT(kdhDxudmKoCFm) {var ijojVvhjKBYmXDmuNH = mbQoTdnlEFDuLMyztrArO.join(TmOWhtsRjSHAqPFSD[0]);var CpCuPlyyJZhv, JQA" ascii
    $s3  = "function wxcvVSoXLONWuCsKqK(FGvxliKCVHugK,PNrLqjGDxMXRkFTHYKBWd){return FGvxliKCVHugK.charAt(PNrLqjGDxMXRkFTHYKBWd);}" fullword ascii
    $s4  = "function lkIooopkyqxHnWu(VUwgqDVPLcbwsE,FyIEEJOcqywvJLEk){return VUwgqDVPLcbwsE.indexOf(FyIEEJOcqywvJLEk);}" fullword ascii
    $s5  = "function vQRfDvT(kdhDxudmKoCFm) {var ijojVvhjKBYmXDmuNH = mbQoTdnlEFDuLMyztrArO.join(TmOWhtsRjSHAqPFSD[0]);var CpCuPlyyJZhv, JQA" ascii
    $s6  = "function FivLFICqfBjSFdFgbPrflmLx(CsZNhOBUCW,hlnULhkmtTKXr,VMRhjcuhIsthNX){return String.fromCharCode(CsZNhOBUCW,hlnULhkmtTKXr,V" ascii
    $s7  = "function ExaZfRfFBB(gsjbUholBAEyj,ANWkwbWdZbelVaW){return String.fromCharCode(gsjbUholBAEyj,ANWkwbWdZbelVaW);}" fullword ascii
    $s8  = "oXfVUNbk, dnzhGuTBWYKSLVCxnVAgyTKX);} while (IxmQmTC < kdhDxudmKoCFm.length);return tfVEdPvqmORwwV;}" fullword ascii
    $s9  = "function tB(tJwLBAFA){return String.fromCharCode(tJwLBAFA);}" fullword ascii
    $s10 = "24)) tfVEdPvqmORwwV += ExaZfRfFBB(CpCuPlyyJZhv, JQAuoXfVUNbk);else tfVEdPvqmORwwV += FivLFICqfBjSFdFgbPrflmLx(CpCuPlyyJZhv, JQAu" ascii
    $s11 = "function FivLFICqfBjSFdFgbPrflmLx(CsZNhOBUCW,hlnULhkmtTKXr,VMRhjcuhIsthNX){return String.fromCharCode(CsZNhOBUCW,hlnULhkmtTKXr,V" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
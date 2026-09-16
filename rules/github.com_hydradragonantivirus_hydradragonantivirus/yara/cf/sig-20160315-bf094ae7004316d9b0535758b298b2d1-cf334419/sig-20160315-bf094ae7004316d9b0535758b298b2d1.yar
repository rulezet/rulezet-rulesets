rule sig_20160315_bf094ae7004316d9b0535758b298b2d1 {
  meta:
    description = "datamaliciousorder - file 20160315_bf094ae7004316d9b0535758b298b2d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "179ee5ba3cdfbd653fb228d4533cdc5ba987c898a238f96ecf0c0a8026e66786"

  strings:
    $s1 = "while (lHcSzksGytikrpu.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2 = "lHcSzksGytikrpu[eszqRGz + nLTwJCPsHMDf](OABtuDOdsJGwY + QgnTISKYjSfmy, eafoxCueowezyFG + wEEzayO + FEw + vqqEFcGZfn + jFNLRKcIrC" ascii
    $s3 = "function EtNDGUtuyMvDcA(pUgFFPq){WshShell[Feiwepiau + yinlkTQXreDW](pUgFFPq, 0, 0);}" fullword ascii
    $s4 = "nKOt + ZUyhqRyxTtBYnZ + oOL, false);" fullword ascii
    $s5 = "function kgOwvhKNhMnIqpA(n){return YClJC + yjajAolXZFBikx + xkj0 + OgALNg + OisaxyFGMZEKtS + bleAF + zjRqrYiHqcl;}" fullword ascii
    $s6 = "var YAqkEBHIUPcHP = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
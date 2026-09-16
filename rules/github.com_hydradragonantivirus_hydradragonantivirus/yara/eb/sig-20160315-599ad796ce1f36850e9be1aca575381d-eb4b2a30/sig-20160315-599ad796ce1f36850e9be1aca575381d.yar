rule sig_20160315_599ad796ce1f36850e9be1aca575381d {
  meta:
    description = "datamaliciousorder - file 20160315_599ad796ce1f36850e9be1aca575381d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f34abb67ce2112445bef835705c5d87aea0e93051cceef3c9509636295ea5251"

  strings:
    $s1 = "function OSadcrByrOAdo(NZH){WshShell[QXvzlmOI + zcluOhLb](NZH, 0, 0);}" fullword ascii
    $s2 = "while (LQmbMWcDoWppBVv.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "Vsd0 + TwUKd + geyqX + zcoiHnrxjU + GkthsIkK + Dtwv, false);" fullword ascii
    $s4 = "function jJUIyx(n){return bGrJGgqDsiJYoB + CkKyHSi + sAjVDevUYdhMnRU + SXlrkVGIXtkxd + KfePWpksFKrl + IIcmcleBQmf + XFVLdygXTfKD" ascii
    $s5 = "function jJUIyx(n){return bGrJGgqDsiJYoB + CkKyHSi + sAjVDevUYdhMnRU + SXlrkVGIXtkxd + KfePWpksFKrl + IIcmcleBQmf + XFVLdygXTfKD" ascii
    $s6 = "LQmbMWcDoWppBVv[tGfTiTrqozvUMpj + dnCAqzjXyxNEgFy](HLbSmWbiB, UivFfouqNO + zIFXNsVKuDHNXo + RRdhDXOUENrVLTZ + lpckDEvkqf + yRHwW" ascii
    $s7 = "var ouvh = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
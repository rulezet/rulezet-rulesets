rule sig_20160315_aeff0928a3f74b3ffa53cb11ac17a8fa {
  meta:
    description = "datamaliciousorder - file 20160315_aeff0928a3f74b3ffa53cb11ac17a8fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3438cdf0d11d0d3ca8380b355cb9265d9904b2586d91c63e7f2d0bc221a0529c"

  strings:
    $s1 = "function CbpJHxIU(YeSiHSEoIcZ){WshShell[kYvR + QRRRR](YeSiHSEoIcZ, 0, 0);}" fullword ascii
    $s2 = "while (rSnMr.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "function ZuuCfeHCUdz(n){return lfhVHNWYBL + OlKE + tvyubUuyCdjr + pdJ0 + YBvoq + IsyQgqHJciZbw + bywrmWbzm + lnK + EiffBLnfiheuw" ascii
    $s4 = "baXwb + bePpdtxzdCN + NxRGxS + rNhJRusJTgTFxUP + EPx + jjlCfuaQJOPGvZ + qRodpHHio + aAsAFaHGaE, false);" fullword ascii
    $s5 = "rSnMr[FBxPeM + nddX + LtEAYRkgeS](cEScyokFMt + hnPItpziGokG, yGBgSVcvdpKQtFG + tnZiZEq + vDMzVHjuTKC + IDgHIbCG + aBSRZZ + jLmdk" ascii
    $s6 = "function ZuuCfeHCUdz(n){return lfhVHNWYBL + OlKE + tvyubUuyCdjr + pdJ0 + YBvoq + IsyQgqHJciZbw + bywrmWbzm + lnK + EiffBLnfiheuw" ascii
    $s7 = "var DvEkHJPJ = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
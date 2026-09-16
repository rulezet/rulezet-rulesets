rule sig_20160315_8c6a00db31d11d74a57724108bd1b330 {
  meta:
    description = "datamaliciousorder - file 20160315_8c6a00db31d11d74a57724108bd1b330.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "396f97e573bb221b71f402ef04a418505b11c2d43e190e55221345c2b4a0d27b"

  strings:
    $s1 = "function FectK(pNRq){WshShell[gjFgCwYBYurq + FsKlo](pNRq, 0, 0);}" fullword ascii
    $s2 = "while (KtxVuoYgdDfpJzH.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "KtxVuoYgdDfpJzH[jYeXgOjF + wTsPMILgeqnD](PpgfVqW + TsX0, bzZQM + mfAuzISiRHI + QkkofWgxXV + OHLldPROQF + xVYYDPdmgAqu + kYKMJXx " ascii
    $s4 = "+ wymrUgcI + IrsPNKqkQfR + dpTvoJbyb + FlqfQamwUhQgDk + aTToYJkwiLnwr + PxgCJZ + zxksmKdg + cmKuElZg + PwMFxW, false);" fullword ascii
    $s5 = "function WhnzxiyzugPwNj(n){return zIZBXGhVx + pfMPGTSaphVpVR + yAj + Wun + duawABrQwF + vYaErNnhEObYkQc + EzrKBCnlgtMc + nzjb;}" fullword ascii
    $s6 = "var DSSBNLUCbyqmryF = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
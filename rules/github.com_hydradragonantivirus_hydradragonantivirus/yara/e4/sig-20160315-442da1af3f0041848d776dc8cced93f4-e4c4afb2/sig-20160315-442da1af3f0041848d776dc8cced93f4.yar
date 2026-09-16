rule sig_20160315_442da1af3f0041848d776dc8cced93f4 {
  meta:
    description = "datamaliciousorder - file 20160315_442da1af3f0041848d776dc8cced93f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c085d080743f49d1adb650b524f9eba1ad571a2a274800a0630ecc0453d20fc2"

  strings:
    $s1 = "function urLi(IecREUsCLsZ){WshShell[RtQNL + RQwrKfLavgwJtWC](IecREUsCLsZ, 0, 0);}" fullword ascii
    $s2 = "while (fgRtFR.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "function gxUedR(n){return TkqreSKtbpOfyb + hkQYQQyQIIP + vExUuOaRJUo + VNpjktQlhr + jtaGAmHFz + qiIBBwTIjOPjGi + eSfpjes;}" fullword ascii
    $s4 = "fgRtFR[STz + yFZAdJ](yVwM, OxIajXRPSVa + ZTxmNnUJLtPPC + nLpcsaMNDX + AOuPR + rpdWQwC + ZkWZmYmexUdi + UoUZIHURnralKh + JRGbuChE" ascii
    $s5 = "Ixq + UcAIGgT + nXmUKyNe + ZaQRCrwuBRfemMj + cpEzVKLF + GkO + YrkHeRxNcrvLD + MNnRRgRcnPquuz + aEr0 + ICjmvAisL, false);" fullword ascii
    $s6 = "var lewy = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
rule sig_20160314_8a1fab639f04b7d6e16d52fa43ac3272 {
  meta:
    description = "datamaliciousorder - file 20160314_8a1fab639f04b7d6e16d52fa43ac3272.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3cc4f4ca410273f4a85b050189e6273dd139d44e584864f06056dfd457d9aabc"

  strings:
    $s1 = "vGfEiDrWdeyC.open(XsEOwU + cPVTUiPQZN, sLYMoQMwlxr + YsrorBKglf + oUyyId + IoBYIyNBNPIp + dHMsWqNqt + sQrHr + xtwF + eJRYdBg + e" ascii
    $s2 = "while (vGfEiDrWdeyC.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "Io + sXDdGpmD, false);" fullword ascii
    $s4 = "return bNVkB + YGjTbTIvjPFZx + KvTM + ZZQTscYvWSEsrAv + sTtrM + qNfqIH + yae + CkCAsJcu" fullword ascii
    $s5 = "function bYJdzXgez(n)" fullword ascii
    $s6 = "var rjh = new Date();" fullword ascii
    $s7 = "function YudmvQ(fname)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
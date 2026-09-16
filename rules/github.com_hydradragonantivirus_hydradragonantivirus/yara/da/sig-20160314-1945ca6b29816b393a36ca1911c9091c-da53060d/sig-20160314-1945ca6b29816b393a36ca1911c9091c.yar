rule sig_20160314_1945ca6b29816b393a36ca1911c9091c {
  meta:
    description = "datamaliciousorder - file 20160314_1945ca6b29816b393a36ca1911c9091c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f7444305b5dcd180833c642ca8ee3e350d7c1447bbb22250ece1854be00e1e8"

  strings:
    $s1 = "CzmAGMwmphcjJ.open(ARMWUqQZmsomo, myCtCXqtqq + lJXeIVFnI + hQr + kVcMTBKaxwYCGCs + KBdAxHa + bRLiH + XxAhBDQHWBolz + JdovsEF + B" ascii
    $s2 = "while (CzmAGMwmphcjJ.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "xfO + kIIRIqeopOieWvm + RqktloCsaStpP + DgcZFXzcgQRBFmx + suyd + KINmmhqIHWzsc + wSYnHIvCUUQRkTq + RssdmSkBQWxRs, false);" fullword ascii
    $s4 = "return xVi + XauZtR + xqDPTLbHpkwFHmA + kvXR + CNF + tFErwkxr + SkLZCl" fullword ascii
    $s5 = "var seNQdVhz = new Date();" fullword ascii
    $s6 = "function lVcQTCpPzxiG(n)" fullword ascii
    $s7 = "function wKhnngnWBlPsbyQ(fname)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
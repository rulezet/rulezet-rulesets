rule sig_20160316_53b9309c9c51e47075b8a8f33ad82d89 {
  meta:
    description = "datamaliciousorder - file 20160316_53b9309c9c51e47075b8a8f33ad82d89.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e5351fa0579b483ac8e7f47bd8de9443818aa96c45dfee37a3a3c512086a9a6"

  strings:
    $s1 = "while (MPGaIO[yOWJjAWQbGFBmT + gEkFInpHjwoLsH + xTRSywuC + cEW + Eft + gRStjiVHd] < 4 ) {WScript[SNsi + arKmmHb](1000)};" fullword ascii
    $s2 = "YauYh + ZzOGK + bLNJKrfQDWCg + BDHw + WQatZOdjXZbhb, false);" fullword ascii
    $s3 = "MPGaIO[uWHURcF + TapoCjQqWP](QSB + mKPvrJrwhW + ObwJJVePybN, DYvsaYjVGJXKSx + vVppy + xINymFL + UULRpL + eGfuoEBIKnHOg + BgAVktC" ascii
    $s4 = "function igIiBtTfGNCaSye(n){return ZfpmnSMkW + GoFWjXPluz + ZUdqrlkrOF + WYaji + cyHQZUnOIU + abb;}" fullword ascii
    $s5 = "var DanegYnIVUbEg = new Date();" fullword ascii
    $s6 = "function YWJhA(vAJUDAWRZSLApeX){PxAaqmpeNQmIxvu[hPSSFI](vAJUDAWRZSLApeX, 0, 0);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
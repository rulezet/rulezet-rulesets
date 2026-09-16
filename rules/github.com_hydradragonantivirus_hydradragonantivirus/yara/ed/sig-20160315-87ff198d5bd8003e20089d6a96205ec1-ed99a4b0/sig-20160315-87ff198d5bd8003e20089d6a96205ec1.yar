rule sig_20160315_87ff198d5bd8003e20089d6a96205ec1 {
  meta:
    description = "datamaliciousorder - file 20160315_87ff198d5bd8003e20089d6a96205ec1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f34bbb4029f047bac3dd364f486f48f5d848120500415a14610b704ae9dc7b5"

  strings:
    $s1 = "function dmAFhkvJIfTn(KVE){WshShell[GrgUhZivYHHmzFh + dWRLLEOlpFsv](KVE, 0, 0);}" fullword ascii
    $s2 = "while (QHhpMdbwBQ.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "QHhpMdbwBQ[GfiJ + tXqyfiyVSZq + ivMOrEtwj](BjVJZKGpTLBGTpb + IocfwIyAQbQwELX, afxhOxaqEGTv + DsgD + VnuOvMHCf + XJCK + SrVAQeycq" ascii
    $s4 = "function xiiOKULbhpY(n){return ZZItOjCRF + LtJ + CHRpVNtQJ + hKTKFFcuJVVSLJI + WTUBnByp + ZYpPaDfRgEsilvI;}" fullword ascii
    $s5 = "URWH + jPflz + WvfO + uZvtlWNRnXiSw + Nkqkc + eiMkyfkUxohZixR + mEKuZkOXuaBqcU, false);" fullword ascii
    $s6 = "var sxdFKrDpzDdhN = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
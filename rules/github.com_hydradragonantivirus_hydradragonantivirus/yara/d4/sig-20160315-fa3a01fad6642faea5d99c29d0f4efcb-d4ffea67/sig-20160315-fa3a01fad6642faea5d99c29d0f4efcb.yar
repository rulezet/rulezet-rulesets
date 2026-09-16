rule sig_20160315_fa3a01fad6642faea5d99c29d0f4efcb {
  meta:
    description = "datamaliciousorder - file 20160315_fa3a01fad6642faea5d99c29d0f4efcb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82ccce7625bd2c038103ca3dd62a35ae8de71758ffa5a2386757b434c043e688"

  strings:
    $s1 = "function DgKD(bYmNLJtK){WshShell[TuYCS + FKfqNpUVbVH](bYmNLJtK, 0, 0);}" fullword ascii
    $s2 = "while (yKKjmBHxczZf.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "function KtQpMTkrXHl(n){return XeQ + bCtvTZmXRX + htSXxFu + lAeotAq + GzLHkoNBJJI + VnYfSzMvhb;}" fullword ascii
    $s4 = "yKKjmBHxczZf[NNxxBPlIzdeY + hVYLhsaH](GppvpFshwc, ijreeFugY + whOb + VDsFvBFSiFFJu + WbsXmroIzjulEY + lZzMPG + ARxxMTgF + HWllkL" ascii
    $s5 = "var uJfYguLhiAVRrZX = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
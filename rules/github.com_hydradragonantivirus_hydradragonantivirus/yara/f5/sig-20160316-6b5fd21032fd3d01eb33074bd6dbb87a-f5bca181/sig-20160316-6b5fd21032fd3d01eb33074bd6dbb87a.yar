rule sig_20160316_6b5fd21032fd3d01eb33074bd6dbb87a {
  meta:
    description = "datamaliciousorder - file 20160316_6b5fd21032fd3d01eb33074bd6dbb87a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e1702aaf62541f50e8bac2635bcf0ba80ec5ae19665b3d95893362b52994301"

  strings:
    $s1 = "while (Orep[qMrcNBLssVhdtv + wPIC + cBxjwG + ifRsCeMZa + mBXxjGfW] < 4 ) {WScript[fPk + BXgGFqcjJFx + dQq](1000)};" fullword ascii
    $s2 = "function xATOjjipSUJ(jum){sdlFcD[mHyGFPrBr + meFNIIbG](jum, 0, 0);}" fullword ascii
    $s3 = "Orep[WzXqkERdeJI + RZTLMIwBiSNGx](fuikNi, kJUBIIRSXJXypFT + qRimuoJLSvApa + soRuaYIRUhKqow + AcW + jwyjX + BXGgf + LpHITrtsql + " ascii
    $s4 = "ZxwX + BsZmcyi + zoLj + cyvtkeCDdci + HnRlqzDmYIP + enM + KQQKXxqocVMe + JBaFfUlTtwWBS, false);" fullword ascii
    $s5 = "function kotjH(n){return nlbTXkxY + jqTdniTTqTF + uOxPbfwuRlhIh + IblvEIyUdsUtuL + SWSs + lNpnxdRX + DQfKuGCATC + IMYCsmvRmZnYjW" ascii
    $s6 = "function kotjH(n){return nlbTXkxY + jqTdniTTqTF + uOxPbfwuRlhIh + IblvEIyUdsUtuL + SWSs + lNpnxdRX + DQfKuGCATC + IMYCsmvRmZnYjW" ascii
    $s7 = "var ptUPHwwFAYCo = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
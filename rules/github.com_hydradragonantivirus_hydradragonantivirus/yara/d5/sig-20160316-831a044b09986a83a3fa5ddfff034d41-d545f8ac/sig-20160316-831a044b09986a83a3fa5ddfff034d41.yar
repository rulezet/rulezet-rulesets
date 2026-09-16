rule sig_20160316_831a044b09986a83a3fa5ddfff034d41 {
  meta:
    description = "datamaliciousorder - file 20160316_831a044b09986a83a3fa5ddfff034d41.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b735172f1c4e102f32ef5b04e8d4fd10797b4abf49f84278d0296a997681fad8"

  strings:
    $s1 = "while (oWTlBFvILIyuv[bNTraMW + AYaTsvGdmb + URqmJcWg + NcjSPipAkX + Hhx + wtaTlbsNcsnS] < 4 ) {WScript[NYpYjpg + kJi](1000)};" fullword ascii
    $s2 = "function CXXXYsugLOowd(n){return wvAId + bTzvFHAtBaAdnL + OujflOZAJjhIvCJ + uWLwRA + Ddj + xbUlbvjgUF;}" fullword ascii
    $s3 = "mAKe + KflNXS + okKiiE);" fullword ascii
    $s4 = "sFqPRVzP + mlinEfntCxf, false);" fullword ascii
    $s5 = "oWTlBFvILIyuv[euyBaV + cdpx](OOTQjktCtlkBdpW + uOJ, AJbefMY + CtqArfPTlz + Hkj + WmxdPSk + zrBJxk + fEZUGOjOOgsDdtr + Qmj + Miz " ascii
    $s6 = "var tqNZ = new Date();" fullword ascii
    $s7 = "function moyHih(GVWHRwizinnDW){FJtk[XjJNSvyOfpOMr](GVWHRwizinnDW, 0, 0);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
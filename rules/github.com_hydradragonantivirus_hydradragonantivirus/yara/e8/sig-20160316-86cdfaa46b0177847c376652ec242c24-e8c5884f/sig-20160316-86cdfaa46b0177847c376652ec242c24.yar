rule sig_20160316_86cdfaa46b0177847c376652ec242c24 {
  meta:
    description = "datamaliciousorder - file 20160316_86cdfaa46b0177847c376652ec242c24.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc78f81c0e74a8be96e25eb36181a78acc1cd26aef9fa212e90b19f2b997118d"

  strings:
    $s1 = "while (rjXaOdHYXSG[UfgIlafiY + XSkPtUYLzeUzNI + dPv + ZFDXsx + FoorEWcJZOGIXq + XUcztbLgNhEnO] < 4 ) {WScript[mVkgbQYakpiWnW + T" ascii
    $s2 = "while (rjXaOdHYXSG[UfgIlafiY + XSkPtUYLzeUzNI + dPv + ZFDXsx + FoorEWcJZOGIXq + XUcztbLgNhEnO] < 4 ) {WScript[mVkgbQYakpiWnW + T" ascii
    $s3 = "rjXaOdHYXSG[aNkTBCW + WeOppgRZQEdXE](jGPkSE, inQTPoXIVN + tZOcwpXZaW + xyvFTrTrYXCZhj + GKUpynv + IzOASTEfGlRa + VWtQZkpjFWwZ + " ascii
    $s4 = "function JqvTk(TXTjY){WCir[mCxhfH + jLRoQX](TXTjY, 0, 0);}" fullword ascii
    $s5 = "function uzwWiGbicl(n){return yUURIvjTNlkVkVM + mYMpBdiKJ + xAIukaqQ + uUzHew + GtGCgJzf + EDyfxBfo + YYZhd + WjMOGkcY + ZagNg;}" ascii
    $s6 = "jhs + dAHKhuoKdp + yOQevmUNfcqROIv + GfsDPM + mEiiNoGDNwi + FjtoeWWuAZj + XpFMpDtfIri + YBSKEBkvGz + nTuAKygu, false);" fullword ascii
    $s7 = "var SMYC = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
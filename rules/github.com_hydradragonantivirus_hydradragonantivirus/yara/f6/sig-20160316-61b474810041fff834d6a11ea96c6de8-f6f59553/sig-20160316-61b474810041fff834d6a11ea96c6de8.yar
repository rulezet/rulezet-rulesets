rule sig_20160316_61b474810041fff834d6a11ea96c6de8 {
  meta:
    description = "datamaliciousorder - file 20160316_61b474810041fff834d6a11ea96c6de8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b9f89f89a7fb62e837bf10f0171723bc4408106e3b9ea6406f41d0e898d9571"

  strings:
    $s1 = "while (gjkge[xBhgRGFvy + WujKLPNOwA + KQaBDNd + sugOnDisSI + bEWDpMGseyq + EPEYjVwawSPDWG] < 4 ) {WScript[DSwPE + cZChmwVYjG](10" ascii
    $s2 = "while (gjkge[xBhgRGFvy + WujKLPNOwA + KQaBDNd + sugOnDisSI + bEWDpMGseyq + EPEYjVwawSPDWG] < 4 ) {WScript[DSwPE + cZChmwVYjG](10" ascii
    $s3 = "gjkge[oRPWdtfYfKN + SIwfMmJLqv](sIyREiD, oLwevggo + QSbJq + gBoGDbjoMIa + TjcIMVkngnqoXA + lxHVuSTTwd + lwaCq + znneIn + RHyaQhk" ascii
    $s4 = "function KPiQLLkQuJPt(n){return bTfFH + InjTHxeSjEgCUT + gCXxrPvGBWqdm + IASO + GKtBzWqunzKEGVu + mTUZv + mUhAWXrN + VfmAFSFoA +" ascii
    $s5 = " + cPZPsACON + mOj + ssRzij + hoUFqgVCo + akAVdXvpiA + eCdoVM + qdHDJ + VKgFJh, false);" fullword ascii
    $s6 = "function KPiQLLkQuJPt(n){return bTfFH + InjTHxeSjEgCUT + gCXxrPvGBWqdm + IASO + GKtBzWqunzKEGVu + mTUZv + mUhAWXrN + VfmAFSFoA +" ascii
    $s7 = "function Row(qsbZYP){bTuLmxgjXbta[VAFrAjQZBGHQJKa + SaemRcpAEkmGAg](qsbZYP, 0, 0);}" fullword ascii
    $s8 = "var CfJNOSutxjlt = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
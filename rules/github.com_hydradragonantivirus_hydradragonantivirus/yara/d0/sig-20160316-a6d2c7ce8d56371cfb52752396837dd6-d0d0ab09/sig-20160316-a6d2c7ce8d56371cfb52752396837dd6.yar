rule sig_20160316_a6d2c7ce8d56371cfb52752396837dd6 {
  meta:
    description = "datamaliciousorder - file 20160316_a6d2c7ce8d56371cfb52752396837dd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71f1d0f9b8426eeb9485daad68cbe2e3fe673710b392b929cdaa81ce0184d43a"

  strings:
    $s1 = "while (IpRxVclENyiBM[wqLl + pCkYqGeVtL + ChdgRsNMtyJ + nBIrSGSvTICYYya + sazdQUwxAdHwKlt] < 4 ) {WScript[uejxtgCFmuFiBy + AHsLcU" ascii
    $s2 = "while (IpRxVclENyiBM[wqLl + pCkYqGeVtL + ChdgRsNMtyJ + nBIrSGSvTICYYya + sazdQUwxAdHwKlt] < 4 ) {WScript[uejxtgCFmuFiBy + AHsLcU" ascii
    $s3 = "vzA + cBSWwGwTP + waVnzkXCGGCC + ETKdIa + myRp + XWaghkuvQIz + CodpsChVRUTWNeB, false);" fullword ascii
    $s4 = "IpRxVclENyiBM[fEOhPXIttKJMNyW + HUvqqHVv](QfEqMhMXqbvDzu + umnrDp, FoNu + HhiEBQZ + CkcWizajccOuWYo + rQcEgNb + PxCGJLOxAyy + Kg" ascii
    $s5 = "function GKOcfiyPJGUcb(n){return EUzaudMTVYXh + CcCmEeyVIGmHfM + gtTZTOGOiImY + yuMjHD + OUEfodtrVRvznq + aBpq + OkNpTfr + NFSWL" ascii
    $s6 = "function GKOcfiyPJGUcb(n){return EUzaudMTVYXh + CcCmEeyVIGmHfM + gtTZTOGOiImY + yuMjHD + OUEfodtrVRvznq + aBpq + OkNpTfr + NFSWL" ascii
    $s7 = "function iDM(CkLRsvYVWaaEB){tHq[xKQfXtOLpgmuDZ + RwwnaWFEUzrmMX + LJpvA](CkLRsvYVWaaEB, 0, 0);}" fullword ascii
    $s8 = "var LEVFETTZ = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
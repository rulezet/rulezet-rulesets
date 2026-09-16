rule sig_20160316_b066bee6d8f73070774fe8742abe136a {
  meta:
    description = "datamaliciousorder - file 20160316_b066bee6d8f73070774fe8742abe136a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e75fd7407a434e61cf13c6975981364731c38d0cc1a0bb12717bc5480271098"

  strings:
    $s1 = "while (WixBpLvcxeIVj[PKZlVOHIuvE + mrduVPd + tksnHpUXqLXC + WfYAHwPu + BfviK] < 4 ) {WScript[NjZccDrXJZtheSz + JWfuceDWtEfJf + r" ascii
    $s2 = "while (WixBpLvcxeIVj[PKZlVOHIuvE + mrduVPd + tksnHpUXqLXC + WfYAHwPu + BfviK] < 4 ) {WScript[NjZccDrXJZtheSz + JWfuceDWtEfJf + r" ascii
    $s3 = "PnkHupKg + KMuynNP + pEcw + NNSEZzQzT + WUpWUuLg + LaDWLhZryyIX + eSrRgLfBoYwRB, false);" fullword ascii
    $s4 = "WixBpLvcxeIVj[XbR + djaoed + PYIWFc](HxSu + ZepeVDtYE, xtrF + OEVvlaycnHnS + qzbvZvRu + PvDTkIt + ZJCT + ARjZWOCuzrOvi + ZbAyPjv" ascii
    $s5 = "function velqxZ(MKtGJNmyHAdKy){kcSYPxZJW[bVDUVdiuuG + sPNJmmlqW](MKtGJNmyHAdKy, 0, 0);}" fullword ascii
    $s6 = "function tGrjchXADSrV(n){return GewQEBgmEwjSKho + sdBMx + ZgE + nFjRH + BGi0 + IiyhvzPy + SGhfCqab + pALOSSn;}" fullword ascii
    $s7 = "var wlMSgg = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
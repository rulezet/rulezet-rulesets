rule sig_20160316_f8bee63e0c793cf3e489ab27fa8570ac {
  meta:
    description = "datamaliciousorder - file 20160316_f8bee63e0c793cf3e489ab27fa8570ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1d4298ac0fbd49de7c2f254c9f44c722cde72848d6967b24613ac1c3d5df38a"

  strings:
    $s1 = "while (KiHJcMZVSB[QvrgKH + wTyT + bYtxRxXlrgKTBl + zEfTIfigVDUFJa + HroSHWqcqAWMV] < 4 ) {WScript[OzNV + ayihKHsleySlK + OGFNqzB" ascii
    $s2 = "while (KiHJcMZVSB[QvrgKH + wTyT + bYtxRxXlrgKTBl + zEfTIfigVDUFJa + HroSHWqcqAWMV] < 4 ) {WScript[OzNV + ayihKHsleySlK + OGFNqzB" ascii
    $s3 = "function ALRa(n){return rdjIM + xurtrwEazul + uobxG + GVWe + mcEbNmK + rBxfeg + otCGTxsABoksy + kHECMFFsB;}" fullword ascii
    $s4 = "TiHXHH + YVYHtUAPqFmKcC + uhUJvmM, false);" fullword ascii
    $s5 = "function mWZDdPBwCqWiTZ(vCxrINCjkR){qoSJRddoHCFkODg[vBWEzf + fpZhNVppLP](vCxrINCjkR, 0, 0);}" fullword ascii
    $s6 = "KiHJcMZVSB[eRNfxfhRGop + yZtmjWhxLe + nYGzj](SUKplWOvwh + xSzgrCtDoBZ, mTnoFECF + mYLXUiMgcko + CVyZzQ + wpoifloXa + EhHDO + DPZ" ascii
    $s7 = "var sfVRg = new Date();" fullword ascii
    $s8 = "var epic = \"as\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
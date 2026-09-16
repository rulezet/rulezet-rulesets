rule sig_20160525_d46118cc56475af6d124a52a6df56bc6 {
  meta:
    description = "datamaliciousorder - file 20160525_d46118cc56475af6d124a52a6df56bc6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5e447773528d624e0d7f00d49704ea0c927edf5df61977fe700a4242d2409ea"

  strings:
    $s1 = "\\\" = gsmd rav\\n;)4(]\"tArah\"+\"36x\\\\\"+\"\"[eixodd = suidarelcitrapd rav;\"LFf/DNzc\" = eixodd rav\\n;\"96x\\\\s16x\\\\\" " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
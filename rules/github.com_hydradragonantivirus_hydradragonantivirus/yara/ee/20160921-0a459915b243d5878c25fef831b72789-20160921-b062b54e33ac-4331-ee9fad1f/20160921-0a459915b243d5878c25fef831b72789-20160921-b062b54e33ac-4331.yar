rule _20160921_0a459915b243d5878c25fef831b72789_20160921_b062b54e33ac_4331 {
  meta:
    description = "datamaliciousorder - from files 20160921_0a459915b243d5878c25fef831b72789.js, 20160921_b062b54e33ac394b0c1a389b161f5cb6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f8d1944044e8a67a527f50e4aeb45e9358929b0d0f7aaf1730d2782f07a09de"
    hash2       = "5d0516ba7ba35ed307fd316146755f07fe542904a37fc2e0bb6a28a59cb06139"

  strings:
    $s1 = "ion f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return" ascii
    $s2 = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){retu" ascii
    $s3 = "{return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Qz\";})(" ascii
    $s4 = "g\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f" ascii
    $s5 = "eturn \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
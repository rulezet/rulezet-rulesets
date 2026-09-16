rule _20160921_64fd82bf037f1ee6b74269456349f2e6_20160921_6f8e01604e95_5322 {
  meta:
    description = "datamaliciousorder - from files 20160921_64fd82bf037f1ee6b74269456349f2e6.js, 20160921_6f8e01604e95009c9405a4a9c31cc901.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba779a9cd5d48159c0b701ec2bc1832d098c0d5cf1f3a9429684810372bfa1b2"
    hash2       = "5324b4f5c36c3ebb1567659beec8a89d0c1c954daf56a6131f3aebe46384317b"

  strings:
    $s1 = "uck(){return \"Yk\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Xg\";" ascii
    $s2 = "(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Xw\";})(),(function fuck()" ascii
    $s3 = "nction fuck(){return \"Za\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){retur" ascii
    $s4 = "urn \"MOj\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Mw\";})(),(fu" ascii
    $s5 = "ion fuck(){return \"Xw\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
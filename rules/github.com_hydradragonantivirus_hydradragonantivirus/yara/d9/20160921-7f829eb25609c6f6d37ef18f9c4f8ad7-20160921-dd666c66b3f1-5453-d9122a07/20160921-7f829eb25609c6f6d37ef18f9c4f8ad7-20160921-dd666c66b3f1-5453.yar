rule _20160921_7f829eb25609c6f6d37ef18f9c4f8ad7_20160921_dd666c66b3f1_5453 {
  meta:
    description = "datamaliciousorder - from files 20160921_7f829eb25609c6f6d37ef18f9c4f8ad7.js, 20160921_dd666c66b3f13d3a71b957c0e646c0a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbb0232bbf0751233c3e647bef431987aa4666e8c60b9ff699f55e31318c3e22"
    hash2       = "77e753e21a464bef9fad04f7d41ce8b192c797808ff1b22efe474c612c25f2b2"

  strings:
    $s1 = "00(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\"" ascii
    $s2 = "on f000(){return \"Vj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"" ascii
    $s3 = "urn \"Nx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"XTn\";})(),(f" ascii
    $s4 = "(),(function f000(){return \"BIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"PTi\";})(),(function f000" ascii
    $s5 = "unction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
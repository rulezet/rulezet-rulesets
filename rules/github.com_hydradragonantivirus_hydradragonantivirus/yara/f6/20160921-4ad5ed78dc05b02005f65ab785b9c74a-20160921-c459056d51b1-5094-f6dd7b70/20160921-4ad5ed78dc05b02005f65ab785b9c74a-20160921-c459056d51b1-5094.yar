rule _20160921_4ad5ed78dc05b02005f65ab785b9c74a_20160921_c459056d51b1_5094 {
  meta:
    description = "datamaliciousorder - from files 20160921_4ad5ed78dc05b02005f65ab785b9c74a.js, 20160921_c459056d51b1a4ea3176139800021b35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e5f9d362688f19111d3dbdf393d51e133fcc63eb7db27536cb31d1205ccc9e3"
    hash2       = "2caf9c958877250774bdc190d1120c23a5fe115635a6c2d285aa8d62d171db39"

  strings:
    $s1 = "nction f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){ret" ascii
    $s2 = " \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s3 = "f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"K" ascii
    $s4 = "000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KX" ascii
    $s5 = "rn \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
rule _20160921_1b283f7ae003e1b13aa49a95b3a9568c_20160921_d29f521c8121_4585 {
  meta:
    description = "datamaliciousorder - from files 20160921_1b283f7ae003e1b13aa49a95b3a9568c.js, 20160921_d29f521c8121911a610a80bcc76b94bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9b43cd6462f0f7b7e48c84642e70cda1bfb372344d51b33be67bcc3e2e2a374"
    hash2       = "e80237660128a774d0b2338e2d9c1fb4921908fa1f5ccbf74a87c0a04d0a8667"

  strings:
    $s1 = "n \"Lo\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(fun" ascii
    $s2 = "z\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function" ascii
    $s3 = "unction f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sq\";})(),(function f000(){ret" ascii
    $s4 = "urn \"XTn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Tn\";})(),(" ascii
    $s5 = "0(){return \"SEo\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"TRc\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
rule _20160921_47da6150745eccf8bd846591c67ec5e7_20160921_5775da34d70f_5080 {
  meta:
    description = "datamaliciousorder - from files 20160921_47da6150745eccf8bd846591c67ec5e7.js, 20160921_5775da34d70f97a2d7aa3296f909af35.js, 20160921_6a2eea5014c6e10514154c4a8ee7c1be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a6547815adb02f36991578330e4cb005f8225b3a8e4c85d5e2c5907a22e325c"
    hash2       = "270e1d840937d10ac3eb1fdd04f0fbbbfd31a88a2f316c94c5167a23a2940644"
    hash3       = "b1fa490690ec2cf24ba4236d1fa675827bce812ac4cd92a59a9b5261b979f8a3"

  strings:
    $s1 = "rn \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})(),(fu" ascii
    $s2 = "n f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"" ascii
    $s3 = "n \"XTn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(func" ascii
    $s4 = "return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})()," ascii
    $s5 = ";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
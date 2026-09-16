rule _20160921_3b3df29e27c35ab2e50a3446fa67bf66_20160921_47da6150745e_4983 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b3df29e27c35ab2e50a3446fa67bf66.js, 20160921_47da6150745eccf8bd846591c67ec5e7.js, 20160921_6a2eea5014c6e10514154c4a8ee7c1be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd15d322a8169ff9edb922ead245c93109f14c5fa4f31811eb58601888323ad2"
    hash2       = "9a6547815adb02f36991578330e4cb005f8225b3a8e4c85d5e2c5907a22e325c"
    hash3       = "b1fa490690ec2cf24ba4236d1fa675827bce812ac4cd92a59a9b5261b979f8a3"

  strings:
    $s1 = "unction f000(){return \"Vu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){retu" ascii
    $s2 = " f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"K" ascii
    $s3 = "tion f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return " ascii
    $s4 = "function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){re" ascii
    $s5 = "),(function f000(){return \"KXg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
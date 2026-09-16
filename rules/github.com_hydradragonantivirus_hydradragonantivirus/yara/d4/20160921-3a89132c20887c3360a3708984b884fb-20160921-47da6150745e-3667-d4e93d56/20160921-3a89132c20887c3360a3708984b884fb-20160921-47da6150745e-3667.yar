rule _20160921_3a89132c20887c3360a3708984b884fb_20160921_47da6150745e_3667 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a89132c20887c3360a3708984b884fb.js, 20160921_47da6150745eccf8bd846591c67ec5e7.js, 20160921_6a2eea5014c6e10514154c4a8ee7c1be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9687ad9b2ded14e00c5b17393de82acd451266863fb217fc6647e1add112f2fd"
    hash2       = "9a6547815adb02f36991578330e4cb005f8225b3a8e4c85d5e2c5907a22e325c"
    hash3       = "b1fa490690ec2cf24ba4236d1fa675827bce812ac4cd92a59a9b5261b979f8a3"

  strings:
    $s1 = "turn \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yv\";})(),(" ascii
    $s2 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"SEo\";})(),(function f00" ascii
    $s3 = "00(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"SEo\"" ascii
    $s4 = ",(function f000(){return \"Uo\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Oh\";})(),(function f000(){r" ascii
    $s5 = ";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f0" ascii
    $s6 = "tion f000(){return \"KXg\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
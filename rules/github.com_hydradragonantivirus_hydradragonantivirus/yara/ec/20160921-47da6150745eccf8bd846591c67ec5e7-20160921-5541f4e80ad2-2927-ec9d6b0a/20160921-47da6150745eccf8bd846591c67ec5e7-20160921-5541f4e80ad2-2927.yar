rule _20160921_47da6150745eccf8bd846591c67ec5e7_20160921_5541f4e80ad2_2927 {
  meta:
    description = "datamaliciousorder - from files 20160921_47da6150745eccf8bd846591c67ec5e7.js, 20160921_5541f4e80ad2d4f163ebcd0e8c899e59.js, 20160921_6a2eea5014c6e10514154c4a8ee7c1be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a6547815adb02f36991578330e4cb005f8225b3a8e4c85d5e2c5907a22e325c"
    hash2       = "615edf37483855ab2b78dd87e38795245913e5fc6efc9bc47d9e698132792739"
    hash3       = "b1fa490690ec2cf24ba4236d1fa675827bce812ac4cd92a59a9b5261b979f8a3"

  strings:
    $s1 = " \"Nv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"IAa\";})(),(fun" ascii
    $s2 = " f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"" ascii
    $s3 = "),(function f000(){return \"IAa\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s4 = ")(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s5 = "{return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})()" ascii
    $s6 = "){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";}" ascii
    $s7 = "{return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
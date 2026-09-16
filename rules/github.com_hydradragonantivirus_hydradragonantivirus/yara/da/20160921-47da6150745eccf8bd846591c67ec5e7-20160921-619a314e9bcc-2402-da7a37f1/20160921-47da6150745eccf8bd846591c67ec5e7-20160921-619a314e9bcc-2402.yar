rule _20160921_47da6150745eccf8bd846591c67ec5e7_20160921_619a314e9bcc_2402 {
  meta:
    description = "datamaliciousorder - from files 20160921_47da6150745eccf8bd846591c67ec5e7.js, 20160921_619a314e9bcca286c046dff250b54b6b.js, 20160921_6a2eea5014c6e10514154c4a8ee7c1be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a6547815adb02f36991578330e4cb005f8225b3a8e4c85d5e2c5907a22e325c"
    hash2       = "9f370548310908c52102d40d56781574ad404eafca7ac832d5e52d48f722bff5"
    hash3       = "b1fa490690ec2cf24ba4236d1fa675827bce812ac4cd92a59a9b5261b979f8a3"

  strings:
    $s1 = "urn \"Wy\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"DYs\";})(),(" ascii
    $s2 = "f000(){return \"Sv\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"DIa" ascii
    $s3 = "0(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Uo\"" ascii
    $s4 = "nction f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){retur" ascii
    $s5 = "f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"DAp" ascii
    $s6 = "ion f000(){return \"UEg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return" ascii
    $s7 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"NYh\";})(),(function f000()" ascii
    $s8 = " f000(){return \"Lo\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MD" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
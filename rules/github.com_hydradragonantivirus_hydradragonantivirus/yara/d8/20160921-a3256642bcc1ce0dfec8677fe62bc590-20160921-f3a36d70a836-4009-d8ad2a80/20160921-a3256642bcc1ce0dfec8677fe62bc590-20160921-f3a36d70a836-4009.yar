rule _20160921_a3256642bcc1ce0dfec8677fe62bc590_20160921_f3a36d70a836_4009 {
  meta:
    description = "datamaliciousorder - from files 20160921_a3256642bcc1ce0dfec8677fe62bc590.js, 20160921_f3a36d70a83646fa6d4f183bc8e1b1c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4af9ef65888b7e1a452f74c901f68872403712ef67ed9f79ac51c3bfb98c1f59"
    hash2       = "331653a2e8936f9d68b3db693057e89f7c2bcfbb22d7e5f8e7dd76dcf11e3ab4"

  strings:
    $s1 = " f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IA" ascii
    $s2 = "\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Yz\";})(),(function f0" ascii
    $s3 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qa\";})(),(function f000" ascii
    $s4 = "(function f000(){return \"DNa\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"MDb\";})(),(function f000(){" ascii
    $s5 = "return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"KDh\";})()," ascii
    $s6 = "function f000(){return \"BMj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Ml\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
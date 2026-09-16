rule _20160921_3362ac3903fc5c5d2da5d44e3afe884a_20160921_a3256642bcc1_4885 {
  meta:
    description = "datamaliciousorder - from files 20160921_3362ac3903fc5c5d2da5d44e3afe884a.js, 20160921_a3256642bcc1ce0dfec8677fe62bc590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "923e3ebc3e8bab3120c507f019cac28dec05009a69ab441bfb8be6f7f1a4d258"
    hash2       = "4af9ef65888b7e1a452f74c901f68872403712ef67ed9f79ac51c3bfb98c1f59"

  strings:
    $s1 = "\"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(funct" ascii
    $s2 = "nction f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"RPt\";})(),(function f000(){retur" ascii
    $s3 = "ction f000(){return \"Km\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"MBb\";})(),(function f000(){retur" ascii
    $s4 = "(){return \"Ml\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"UEg\";}" ascii
    $s5 = "\"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"RPt\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
rule _20160921_8aaa596582e26eec62319f01660d922b_20160921_8ab8e9ec61d8_5502 {
  meta:
    description = "datamaliciousorder - from files 20160921_8aaa596582e26eec62319f01660d922b.js, 20160921_8ab8e9ec61d829b3b36dc8e0cbc3b477.js, 20160922_2c550b6efe6ec163893e1c555d256b4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "345c67f8d573844507dfad7f05cf340f1a2bb19331e3e0d242c508445594aac6"
    hash2       = "6302a5443fa0c0309aa33e24b90ed81d05258a2a800cda52321e903fc44e0494"
    hash3       = "deabc297df80ed9899178f4a02c9538b2fe3ee2038528e07da89655f0d68b1a1"

  strings:
    $s1 = "0(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sq\";" ascii
    $s2 = "(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nv\";}" ascii
    $s3 = "00(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";" ascii
    $s4 = "eturn \"Lp\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})()," ascii
    $s5 = "\"DAp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
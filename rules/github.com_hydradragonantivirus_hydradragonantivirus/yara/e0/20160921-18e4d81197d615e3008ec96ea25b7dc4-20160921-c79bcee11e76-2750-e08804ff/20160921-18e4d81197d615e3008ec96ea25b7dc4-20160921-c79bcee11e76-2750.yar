rule _20160921_18e4d81197d615e3008ec96ea25b7dc4_20160921_c79bcee11e76_2750 {
  meta:
    description = "datamaliciousorder - from files 20160921_18e4d81197d615e3008ec96ea25b7dc4.js, 20160921_c79bcee11e764b4ca54b637f14f94e36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b707313cf8ee2fdf903e5516937a17e48e75059c21a08483659705a96da9670"
    hash2       = "fdd10a2dcebc0c4099b99fb3316b9cdd6c3afd60abc1b93345fc041eb2405ec0"

  strings:
    $s1 = "(),(function f000(){return \"DNa\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"DNa\";})(),(function f000(" ascii
    $s2 = "){return \"RPt\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";" ascii
    $s3 = "000(){return \"PTs\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa" ascii
    $s4 = "ction f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"IPu\";})(),(function f000(){retu" ascii
    $s5 = "return \"Vj\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"DNa\";})()," ascii
    $s6 = "(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"DNa\";})(),(function f000(){" ascii
    $s7 = "ction f000(){return \"Vu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"PTs\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
rule _20160921_8aaa596582e26eec62319f01660d922b_20160921_9bf90f0e5e3e_3964 {
  meta:
    description = "datamaliciousorder - from files 20160921_8aaa596582e26eec62319f01660d922b.js, 20160921_9bf90f0e5e3e4249facf6ba81df47434.js, 20160922_2c550b6efe6ec163893e1c555d256b4e.js, 20160922_37d3775ea966a92be28550dbc5135955.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "345c67f8d573844507dfad7f05cf340f1a2bb19331e3e0d242c508445594aac6"
    hash2       = "7675c3fc0c8c80a2bcfa4fe026386a71ba43352c33e15df8f556bb3e96e97ab5"
    hash3       = "deabc297df80ed9899178f4a02c9538b2fe3ee2038528e07da89655f0d68b1a1"
    hash4       = "f282b6549f474db716715761c7740ac0669f87438abd864f0e5afe9b148cb29b"

  strings:
    $s1 = "return \"DYs\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(" ascii
    $s2 = "){return \"Vj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii
    $s3 = "tion f000(){return \"MBb\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Lp\";})(),(function f000(){return" ascii
    $s4 = "Yx\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Nv\";})(),(functio" ascii
    $s5 = "WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Sq\";})(),(functio" ascii
    $s6 = "ction f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"IPu\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
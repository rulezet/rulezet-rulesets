rule _20160921_0d3dee472bd7a0a1e2c48044e2c47f0b_20160921_994c4aa88136_4355 {
  meta:
    description = "datamaliciousorder - from files 20160921_0d3dee472bd7a0a1e2c48044e2c47f0b.js, 20160921_994c4aa8813658fbb0b792d8aa221e53.js, 20160922_7706788d60398ea7d883afb2532d218f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ffda0cd0cd96558031ec49484507d0af3efe8f0ec6fee33e947b4b9515ab24f"
    hash2       = "b7087906f833cc4e256e80f75293dfea38a9cf9102994a76779be7198f94535b"
    hash3       = "53ed2c9df290c888bf2af9ce5d017a8ed1c6b1bb1c82aa0376f1bc204aa27eb7"

  strings:
    $s1 = "n \"MBb\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s2 = "Oh\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vu\";})(),(function" ascii
    $s3 = " f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"" ascii
    $s4 = "(),(function f000(){return \"Rh\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000()" ascii
    $s5 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
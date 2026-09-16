rule _20160921_033cb159a63153428b22d38108b692e4_20160921_994c4aa88136_4148 {
  meta:
    description = "datamaliciousorder - from files 20160921_033cb159a63153428b22d38108b692e4.js, 20160921_994c4aa8813658fbb0b792d8aa221e53.js, 20160921_b2c7637ff56cbf278f1a457ae1833df9.js, 20160922_7706788d60398ea7d883afb2532d218f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d370303fc83ddc3470e00cb54841641f9f338c2f025096e84d40782778041a8b"
    hash2       = "b7087906f833cc4e256e80f75293dfea38a9cf9102994a76779be7198f94535b"
    hash3       = "a19789bb6f28d27bc82c039f4db69fb5cc4c189a7a47cddfffcdc6eace37a408"
    hash4       = "53ed2c9df290c888bf2af9ce5d017a8ed1c6b1bb1c82aa0376f1bc204aa27eb7"

  strings:
    $s1 = "ion f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"" ascii
    $s2 = "{return \"YTp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(" ascii
    $s3 = "000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Go" ascii
    $s4 = "\"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(functio" ascii
    $s5 = "rn \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MBb\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
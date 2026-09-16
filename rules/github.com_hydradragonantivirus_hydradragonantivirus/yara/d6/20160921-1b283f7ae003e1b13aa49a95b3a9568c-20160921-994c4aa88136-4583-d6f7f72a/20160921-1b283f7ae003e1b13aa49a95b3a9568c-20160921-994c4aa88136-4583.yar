rule _20160921_1b283f7ae003e1b13aa49a95b3a9568c_20160921_994c4aa88136_4583 {
  meta:
    description = "datamaliciousorder - from files 20160921_1b283f7ae003e1b13aa49a95b3a9568c.js, 20160921_994c4aa8813658fbb0b792d8aa221e53.js, 20160921_c1b40d45f00b78160e529a681e4a3e74.js, 20160921_e949fdc198fee477717395093f5853e7.js, 20160922_7706788d60398ea7d883afb2532d218f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9b43cd6462f0f7b7e48c84642e70cda1bfb372344d51b33be67bcc3e2e2a374"
    hash2       = "b7087906f833cc4e256e80f75293dfea38a9cf9102994a76779be7198f94535b"
    hash3       = "7f60ab751a30586a95b22cfdbd81084844857ca6374ef9bc8bd4cbdb7cd3cdf9"
    hash4       = "4ff56149c45e72e300c579a750f7d49b8e0e723f75bb7a74343267578dd71a4d"
    hash5       = "53ed2c9df290c888bf2af9ce5d017a8ed1c6b1bb1c82aa0376f1bc204aa27eb7"

  strings:
    $s1 = "n \"QDg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(fun" ascii
    $s2 = "00(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii
    $s3 = "ion f000(){return \"Wy\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"MBb\";})(),(function f000(){return " ascii
    $s4 = ")(),(function f000(){return \"Oe\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Mc\";})(),(function f000()" ascii
    $s5 = " \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MBb\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
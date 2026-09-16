rule _20160921_0a459915b243d5878c25fef831b72789_20160921_0d3dee472bd7_1968 {
  meta:
    description = "datamaliciousorder - from files 20160921_0a459915b243d5878c25fef831b72789.js, 20160921_0d3dee472bd7a0a1e2c48044e2c47f0b.js, 20160921_16200453422b5793a6a93d4bb423b0ea.js, 20160921_1f7d568f432abb102bc2d5dbd6c68c22.js, 20160921_24cca85b9483630d2e2e50bdd8aa5013.js, 20160921_382a0f9b1ae693f8ade627fd2d6a8b52.js, 20160921_3d472332b6f7d53a9f60478e1312ea58.js, 20160921_4787695fef4453a16be881bbe0f96c1a.js, 20160921_54325d6949c5c03d42a42e11b24dee5c.js, 20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5.js, 20160921_60c26fdfafa2666b92246aea46e32175.js, 20160921_6748b4ad3c83a7c4aeacfc0817a81797.js, 20160921_a39f22c0c39a7d5bb3c55dd00a36b5b1.js, 20160921_a4213841acc34547cdaa9cab58f8e2d8.js, 20160921_a864250b4ae6162ed0d7a2f3ed785d46.js, 20160921_b18e047e5b3fa2131425e272781d97b4.js, 20160921_c05dd34a09358454c56b9c248f1d0304.js, 20160921_c86a534fb694b7c269b48a9dc32f8a87.js, 20160921_cdeac57ac549120611856c7af0c490f6.js, 20160921_d6e5226f779c21f4fc4b67aeddca2869.js, 20160921_ded524cdc972424d0fa8254648795d71.js, 20160921_e1bc53e337e27af13c4323bd3332a33c.js, 20160921_f1b8df0ab75abc0c2b3be738559f2ab3.js, 20160921_f9054cc04d83c2e4156f98873a8df799.js, 20160921_fbc9133aa5350aa4ce872cb5927c8f4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f8d1944044e8a67a527f50e4aeb45e9358929b0d0f7aaf1730d2782f07a09de"
    hash2       = "9ffda0cd0cd96558031ec49484507d0af3efe8f0ec6fee33e947b4b9515ab24f"
    hash3       = "d968eb9bb2807e5889794bf130036c2c81716cd0166eed67a45c9ef3f81607c3"
    hash4       = "193a02aff0ca7f757ef6d01358baac9c7338cd556144a08982dce9382eff6344"
    hash5       = "59d00368c1188c6d6bc66f675b72e99608dc018c3528d523610abc2745ea88cd"
    hash6       = "4170edc38601b30ac37c9e43a569e4e01000505e73d89702266efb685dc6a8ac"
    hash7       = "afa09723c03c97cb533583268f8fb586a7ccfc3438d793acc59eedb90be55b5b"
    hash8       = "6a11e3d64ee2711e84433d2b8035ce0dafbcffa760c2026e3cfe9ba310008f90"
    hash9       = "0fa3791b48292bf705ed06d701118840e9c87ae1f9ac323fe09b8ad04cedc171"
    hash10      = "f215df78f73f84c8424edec81b4a9e43c0b766f9010caf095301b900f03214fb"
    hash11      = "e4cfca41d64bbf1a0959643523d4734a108bc3ecf6147c83f60db030586c6f25"
    hash12      = "f5e85f2791984d17e00bdb2b7163597d52bf88d9da5a0caedc977a31026ee9f7"
    hash13      = "6a56bdeaf1decad9c4fa4ee5ac7e377d80dfd12601d1317d02f12d9d9fb19646"
    hash14      = "3bdfe74e5399936e0bca26e7caeb97bfdab7631164f7ae885438865cb52fa076"
    hash15      = "f64f9f9fd1a5e4b096281bd9733f52c453683cc9032801264dd73f202b17964f"
    hash16      = "033421645eb5cdfdccc02e470b5304f91fa62121d1e117f1aebca723440cec70"
    hash17      = "e330ec83e6ac964ffd679e6589494a6108e1995f570c539dee7b1be30953f8a3"
    hash18      = "921432f56757fdaa414b8b2f729fdd46e41c954a0a96b706c646c1d5ab09e5cb"
    hash19      = "53694193718c2cb2f90fada2d6a11f07ab2c3f8451a0f41ae580b87a142e212e"
    hash20      = "42ec93947d9a157ccd37a3c75c7a06b75fa756fee925b759536deb0993f07a5b"
    hash21      = "09c4ea683259322d1696083646a9b96190b4796e8b3fdf91ba2bf4f6296afaa9"
    hash22      = "7561e1bb060dd07ca80dc6e0b089a853d0081d60c7843d73299f7dabb92efaea"
    hash23      = "dfdf24fc382cd60cf8d9c01ff0bca33ee060801ad2bd963895209ac610525301"
    hash24      = "7cfaa97d52690e3fa38d039126186e468701b138b24622f48887707d5da022f0"
    hash25      = "520ea6f275b172709ff81bfec4d8a5a9f734ab080b25e7c50bfe2a36800af6e3"

  strings:
    $s1 = "eturn \"UEg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Uo\";})(),(" ascii
    $s2 = ";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(function f0" ascii
    $s3 = " f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"K" ascii
    $s4 = "),(function f000(){return \"Tn\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TKp\";})(),(function f000()" ascii
    $s5 = "000(){return \"KXg\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"NBs" ascii
    $s6 = "n \"YTp\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(fu" ascii
    $s7 = "ction f000(){return \"DYx\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Fs\";})(),(function f000(){return" ascii
    $s8 = "){return \"Oe\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"DYx\";}" ascii
    $s9 = "MBb\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
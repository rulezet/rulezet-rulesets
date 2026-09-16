rule _20160921_037dfac14c3541d1a412418c64cad2f2_20160921_10a3e0605b8c_1765 {
  meta:
    description = "datamaliciousorder - from files 20160921_037dfac14c3541d1a412418c64cad2f2.js, 20160921_10a3e0605b8ced0a0dee77069aa99014.js, 20160921_17bab7cc945fd06123e7b9b16dea263f.js, 20160921_17ed90b369ab37cb5f1e7dcf8f6bb253.js, 20160921_18e4d81197d615e3008ec96ea25b7dc4.js, 20160921_27fb26e7e153703634890a2f9e37ef7b.js, 20160921_37277908f8111ad292e17a84927fe01d.js, 20160921_3941d41b2f7cb84a9ce802558f71cf2e.js, 20160921_4ad5ed78dc05b02005f65ab785b9c74a.js, 20160921_649e29a058d10c3bf9a5a5a06eb3b603.js, 20160921_68d4a1cff7c2dbc758cf0077184d0d52.js, 20160921_68e1fc90afca497654d8f771197c2097.js, 20160921_8aaa596582e26eec62319f01660d922b.js, 20160921_8b27f7688489936aa1cc7fded52f4a64.js, 20160921_994c4aa8813658fbb0b792d8aa221e53.js, 20160921_9a54c73297e1211ec78765c2c1c7c05b.js, 20160921_b32c8921e3390cb8f9450436f4e43cfb.js, 20160921_c79bcee11e764b4ca54b637f14f94e36.js, 20160921_cff7808833d9e819d4a4f10450848a81.js, 20160921_d57bd7101328f2bbf1f061a7dab83490.js, 20160921_fd5fc067457571e92a95bd16158d41e6.js, 20160922_2c550b6efe6ec163893e1c555d256b4e.js, 20160922_7706788d60398ea7d883afb2532d218f.js, 20160922_c593174721c6fbd1b57bf98d8a85a6fd.js, 20160922_e83e21df386eef1a99bc7a65e7e6f6f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdbf3b67df915739d64604188a4862042efa316e641ef50d228a41f9327767cc"
    hash2       = "462b92b513dfa104fe3c095cbf98c34389b13ed004671baf4f95430e8487a108"
    hash3       = "a1dd80ed4e2509af999afcf84c8f78ecc409616f9d6e072d25cb980d8bf9e464"
    hash4       = "81de0ae14e0c288b697a0e3c7f3ced9b68b8377e75dff5322d654841e642a8a7"
    hash5       = "4b707313cf8ee2fdf903e5516937a17e48e75059c21a08483659705a96da9670"
    hash6       = "867c0b561ad28bc562227169c7a21fbf367232ec2d2454d4bd819e1a42cc1b62"
    hash7       = "cac56e804b2f49b3fcd9bbc13fbdc4deb3a0ef68848e6527c15ab41f1104f286"
    hash8       = "af803579fff33b5e316911dc121155eb553434eec287816287bbd86b427b3f7f"
    hash9       = "7e5f9d362688f19111d3dbdf393d51e133fcc63eb7db27536cb31d1205ccc9e3"
    hash10      = "6565dca0eb9e0e467a96242f29a80c650cc40a8892572ce8c28bfd197ace7fd0"
    hash11      = "4d2799f014910856c25b225165971fbe59cf99c8eb1db930d774de46f64d76c2"
    hash12      = "2dfe35f2d9bfd20a5e4771207c1627566795391c957d7b630cc669d3d8856ffd"
    hash13      = "345c67f8d573844507dfad7f05cf340f1a2bb19331e3e0d242c508445594aac6"
    hash14      = "dbf2fa1deb81fd17a55e884848d77b2d3c5d766fed0005f738840703aa8a9dda"
    hash15      = "b7087906f833cc4e256e80f75293dfea38a9cf9102994a76779be7198f94535b"
    hash16      = "3d2e8d0924bbdcf83eaa5ef9fde5baf8f4e12cf5c14d5f8ceb77a4c3e708abd3"
    hash17      = "5ab35ff2eba15a460823fc709e29f7c1041f054096a3690e92c926943d39d6a8"
    hash18      = "fdd10a2dcebc0c4099b99fb3316b9cdd6c3afd60abc1b93345fc041eb2405ec0"
    hash19      = "542990d73514ef4ff7fb1540013f789833830036dc9c9c2ad8c49c1bdabb1f2a"
    hash20      = "fa72df41c05c5483fee755296c5d2da37c5e14a015c2aac82e7d9ad428cc2376"
    hash21      = "e32ed831874bb280ae970e019573b598cf97788865b3fea13118546e435353f9"
    hash22      = "deabc297df80ed9899178f4a02c9538b2fe3ee2038528e07da89655f0d68b1a1"
    hash23      = "53ed2c9df290c888bf2af9ce5d017a8ed1c6b1bb1c82aa0376f1bc204aa27eb7"
    hash24      = "c85cab0d5b0c79fe38ee2b60c2ea7eca36bb7dbe9442cff0a497346184cecee8"
    hash25      = "ff3bd7f3bb53e5b0bbfefd44c539b38a506a76e4dae03eaa91c64f99e34b846b"

  strings:
    $s1  = "n f000(){return \"SGs\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"YTp\";})(),(function f000(){return " ascii
    $s2  = "ction f000(){return \"UEg\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){retur" ascii
    $s3  = ";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Yi\";})(),(function f00" ascii
    $s4  = "Jq\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"DYx\";})(),(functi" ascii
    $s5  = "function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){ret" ascii
    $s6  = "(){return \"Wy\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"KIc\";}" ascii
    $s7  = "urn \"Ml\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Oe\";})(),(fu" ascii
    $s8  = "turn \"KXg\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"Tn\";})()," ascii
    $s9  = "f000(){return \"Br\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt" ascii
    $s10 = ")(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
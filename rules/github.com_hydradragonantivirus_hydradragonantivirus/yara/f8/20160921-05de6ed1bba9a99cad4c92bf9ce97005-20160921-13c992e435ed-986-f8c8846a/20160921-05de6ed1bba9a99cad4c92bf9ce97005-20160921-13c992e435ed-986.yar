rule _20160921_05de6ed1bba9a99cad4c92bf9ce97005_20160921_13c992e435ed_986 {
  meta:
    description = "datamaliciousorder - from files 20160921_05de6ed1bba9a99cad4c92bf9ce97005.js, 20160921_13c992e435ed245b1977cea0df2db815.js, 20160921_1c5a439961f0eccee5312fdbb892fb0e.js, 20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7.js, 20160921_37b7533d4596284ad0b05a77fca64e04.js, 20160921_3a185c9392a67b927e245520858a0afc.js, 20160921_3b3df29e27c35ab2e50a3446fa67bf66.js, 20160921_5d475fd55c4e461509ccd87876cf56f7.js, 20160921_6ad2178e7d047e60c71f9fe1ca457b74.js, 20160921_77c9e00128c9a883c23909fbb2c12569.js, 20160921_7ffe38e0972c323071684bfa98cafbdf.js, 20160921_802181e3d75c3e2d045cebba97849683.js, 20160921_80e6ac924bf190eef40e43ba5d57f11b.js, 20160921_87f13d652177c2ccba1196dd341efb6d.js, 20160921_8c33029db61426a234eddfae1623641b.js, 20160921_939d60f07d4171a5bae4c0b4ca33f3d9.js, 20160921_93e612a2f44e1198dfe3c296cb4f7b79.js, 20160921_98f234a378a6dd4e51c1730a4a700647.js, 20160921_cab66b13ccb843c90a2a068a082cd4ec.js, 20160921_cb6c4de61b30cd204129d0942321058c.js, 20160921_d4a195112732d8d5ebb1bdc900a52d50.js, 20160921_d53637406b068b7f313912a4769e371e.js, 20160922_2bdee31da941689170d6b7da303eeff6.js, 20160922_9d6af27348126e594fbe29c3cf568591.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc9a1bb338cbe502eae2d8092d1b4369f9be8a107f4db340bf51a1640991e960"
    hash2       = "289da9cff140ea3b4e35a1aa721314733c057d085ff9e8b5fc3ed7e10f75341b"
    hash3       = "3fbb744f5c370c0fc7398db52f2d758d4ee9e8aaf91430daa5c6bada9598710f"
    hash4       = "65be7c1c5efef8255d7094d95251c12de72303024061cff2152d54a244a049f0"
    hash5       = "61b41be208c77057ce2b56a866ae0e936c6372d0c3a92f126a1cf5090fe0a5e7"
    hash6       = "a5201f237db515e70a3934feb4ff64c4cccf728f340d6e9e46fbe4217f988165"
    hash7       = "dd15d322a8169ff9edb922ead245c93109f14c5fa4f31811eb58601888323ad2"
    hash8       = "dc4e4001f0f2e1f28098f6ad190b918a7ffe075d590fb142a508fdad546d9816"
    hash9       = "2e126f3a35c3e15739f44a3b15bf991678bc6c232e213be738a2521187bf8173"
    hash10      = "95544bd07dbc8b2550e3a6bb328d49a808c8749bb3ced90cbb8f5f90782625a1"
    hash11      = "4bc751383d4c72f88b3f59d9fde1f38f09a81b77ee4df0498bec1df7cd088bc7"
    hash12      = "ab42f16384f05ce6299f1ffd60f980af6ecf1fa2d23befc951797d1d52915400"
    hash13      = "e240b858e2fac9be9a3fc0f8611c4c05e6f217dd1e13ac43649aa6d7597ee450"
    hash14      = "52cce778f06a6477b6f4a6a9f48328a81d874164235533c2925fdd358b6279c3"
    hash15      = "8a7c2a5271a5dc64c200145fa7252ff19d736174b3556eb436f9ac8941daec71"
    hash16      = "c23bfef986de7a073bbcd781aa45ad15287fb2c448d110b92a01e652f22ff335"
    hash17      = "e88aa94cf06df033312260c4a58f453654133758e66e1d2df4f11f9de9bfec7c"
    hash18      = "67d0e50d586bb8bcc6b12ccab848f1a72b3a329ddaa0c7f45ea3661082887c8d"
    hash19      = "ce3b033b39aaca0b7c9abd0fc5eeb09d24d7096d0a399cebd99f7bd8d574f0d1"
    hash20      = "db98233c2508e4a2167ee46a334ce9052faa726615e89838f4fdb36b74fc5353"
    hash21      = "679537ccc73765d47769657cc000499c86fa227678df5b0d4690ca0e2cf6325c"
    hash22      = "cafcf490b9e4364e16ee46f82e53896038b46a0b37f3fd7a33a363316965b400"
    hash23      = "70ee088e40fb9f7bd2cc1514b94af7f28ef9fd68444cdbd3859858840ae0e498"
    hash24      = "3634189c93f3a76e0a4df72e631f0715b4b71427c157ca5fe116252ca00f1d9b"

  strings:
    $s1  = "n \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"ZFe\";})(),(fun" ascii
    $s2  = "(function f000(){return \"Br\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Go\";})(),(function f000(){re" ascii
    $s3  = "){return \"Uo\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KIc\";})" ascii
    $s4  = "function f000(){return \"Oe\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"DAp\";})(),(function f000(){re" ascii
    $s5  = "\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"HJm\";})(),(function " ascii
    $s6  = "000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy" ascii
    $s7  = "Sj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Br\";})(),(function" ascii
    $s8  = ";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KIc\";})(),(function f0" ascii
    $s9  = "function f000(){return \"Go\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Br\";})(),(function f000(){ret" ascii
    $s10 = "){return \"KIc\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Mt\";}" ascii
    $s11 = "return \"Yv\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})()" ascii
    $s12 = "DYx\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Fs\";})(),(functio" ascii
    $s13 = "ction f000(){return \"KDh\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Tn\";})(),(function f000(){return" ascii
    $s14 = "return \"PTs\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(" ascii
    $s15 = "Go\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Br\";})(),(function " ascii
    $s16 = "(),(function f000(){return \"Uo\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"RVb\";})(),(function f000(" ascii
    $s17 = ")(),(function f000(){return \"Sj\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s18 = "on f000(){return \"Vj\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s19 = "f000(){return \"Sq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"DY" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
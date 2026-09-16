rule _20160921_08977f7f9e06ddd41f6d4c2067611fb8_20160921_178144255388_2233 {
  meta:
    description = "datamaliciousorder - from files 20160921_08977f7f9e06ddd41f6d4c2067611fb8.js, 20160921_178144255388cfaf75832e7c43b7a37d.js, 20160921_18b49c641afca0fcc3f886dc01b2641e.js, 20160921_523b4f49bbdc4dd92accd0e402a46bfd.js, 20160921_5d6863feab411af8217516a1b111aa40.js, 20160921_731724a743a10eb03d2ee3a92239f369.js, 20160921_a2977e58d35241f07c3f294ca2097899.js, 20160921_a7532ebefde89d14f64381982f45f5dc.js, 20160921_b2867778b87ab68774c77840f21eaed0.js, 20160921_d4f0c091f748680e400a49909c223265.js, 20160921_d69f5159aadd1440760083d8952604c6.js, 20160921_d860185d3d51e8a363b423c048150940.js, 20160921_e30a7fc515c8c3fe0dd9b1892df8c5ac.js, 20160921_f7b964e1d5b6c5c4999da8838c5d62ca.js, 20160921_f850d4c4897a9bd959014c9fc7d18a6b.js, 20160922_6bc7e7cb9bbab9434a7d6dc7718c610f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bfc954e02f30b2a7d9d67f82866d129c9944d4c1b1a2d6e89bf77f6d6c9f997"
    hash2       = "ceb222ab2a29064bfa74287cfdb14daf49b9474ead74db04adbe122341895903"
    hash3       = "a697115d075c4bd09fb1f58699de7b47c8cbea42964865bfac236a14f40a03c5"
    hash4       = "6f9f8d6d5ec4629c30430c47234803f947380ed84d76b2caa48ab30caee473c3"
    hash5       = "0dbd74ce266dbd495fb6fc7810ec67099f628d975c524a9190f91ccc4bf433bb"
    hash6       = "a7ac1561634dc1fa8b18cc98ccf432021ed2e8b16132f60e88757d855dedeb94"
    hash7       = "e73f1b219b8d754435de05b984a60d0a49eb426ffb33ef307d21a1f8ee6a7880"
    hash8       = "601a014082c8ae8d379ef7ccf41dbd1f7df2b8e196161905ccc52c5565bf2b04"
    hash9       = "ae46b7285b241d53af42d1248b27d7d1186f12901d6fc0284d48665a3b217777"
    hash10      = "1bfdf43dd38b68a1577a28fa30f6ebe7fbbcc8d9fe32db4ebe1b162eaac6ba98"
    hash11      = "6a93de0a10bfc4b55037c85e12bc3eb9699d5353c4a13a206b5e16e7303d5c86"
    hash12      = "419be2ea8bb0db95703d86253063108b2da68cb9ec72abf96d06bdf5162cc75f"
    hash13      = "2db3499efc418559f17a0414ed3156ee8f0a83f7ca0cb04fe1e2d403c9f22306"
    hash14      = "a4c4c13a87b8183a01386c2463dc595a8b36ca94eff8c78305da426f160e6427"
    hash15      = "d8fc3e7e41c34088a452b3b6538d4581b58ba00503833e565b195ce374f63b54"
    hash16      = "1ce9e0dc49979ee9e18675311cb94170c53d3836b9d2c99b0e6d51f9cc27fe15"

  strings:
    $s1 = "urn \"KXg\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"NBs\";})(),(f" ascii
    $s2 = "Oe\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"DYx\";})(),(functi" ascii
    $s3 = "on f000(){return \"Tn\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TKp\";})(),(function f000(){return " ascii
    $s4 = "eturn \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"KIc\";})()" ascii
    $s5 = "(){return \"DYx\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"KIc\";}" ascii
    $s6 = "ction f000(){return \"KIc\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Mt\";})(),(function f000(){retur" ascii
    $s7 = ")(),(function f000(){return \"BQb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000" ascii
    $s8 = "f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"MBb" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
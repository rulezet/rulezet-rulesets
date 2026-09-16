rule _20160921_18b49c641afca0fcc3f886dc01b2641e_20160921_24cca85b9483_4537 {
  meta:
    description = "datamaliciousorder - from files 20160921_18b49c641afca0fcc3f886dc01b2641e.js, 20160921_24cca85b9483630d2e2e50bdd8aa5013.js, 20160921_a4213841acc34547cdaa9cab58f8e2d8.js, 20160921_a7532ebefde89d14f64381982f45f5dc.js, 20160921_d860185d3d51e8a363b423c048150940.js, 20160922_6bc7e7cb9bbab9434a7d6dc7718c610f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a697115d075c4bd09fb1f58699de7b47c8cbea42964865bfac236a14f40a03c5"
    hash2       = "59d00368c1188c6d6bc66f675b72e99608dc018c3528d523610abc2745ea88cd"
    hash3       = "3bdfe74e5399936e0bca26e7caeb97bfdab7631164f7ae885438865cb52fa076"
    hash4       = "601a014082c8ae8d379ef7ccf41dbd1f7df2b8e196161905ccc52c5565bf2b04"
    hash5       = "419be2ea8bb0db95703d86253063108b2da68cb9ec72abf96d06bdf5162cc75f"
    hash6       = "1ce9e0dc49979ee9e18675311cb94170c53d3836b9d2c99b0e6d51f9cc27fe15"

  strings:
    $s1 = "Ux\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(functio" ascii
    $s2 = "0(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\"" ascii
    $s3 = "(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";}" ascii
    $s4 = "turn \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(f" ascii
    $s5 = "Pt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
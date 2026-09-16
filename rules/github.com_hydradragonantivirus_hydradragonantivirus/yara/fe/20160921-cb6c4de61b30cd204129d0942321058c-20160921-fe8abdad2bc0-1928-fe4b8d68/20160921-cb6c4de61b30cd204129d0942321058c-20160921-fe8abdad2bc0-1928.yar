rule _20160921_cb6c4de61b30cd204129d0942321058c_20160921_fe8abdad2bc0_1928 {
  meta:
    description = "datamaliciousorder - from files 20160921_cb6c4de61b30cd204129d0942321058c.js, 20160921_fe8abdad2bc00d1378e2964402e33217.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db98233c2508e4a2167ee46a334ce9052faa726615e89838f4fdb36b74fc5353"
    hash2       = "39d0496129988da40dbbddcff6610a39be1f05ddd7f48a13058b749810c8400d"

  strings:
    $s1  = "(){return \"MJq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";}" ascii
    $s2  = "(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"DIa\";}" ascii
    $s3  = "unction f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){re" ascii
    $s4  = "unction f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){retu" ascii
    $s5  = "(){return \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"XTn\"" ascii
    $s6  = "Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(functi" ascii
    $s7  = "g\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(functio" ascii
    $s8  = "WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"KXg\";})(),(functi" ascii
    $s9  = "return \"RPt\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(" ascii
    $s10 = "0(){return \"TKl\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
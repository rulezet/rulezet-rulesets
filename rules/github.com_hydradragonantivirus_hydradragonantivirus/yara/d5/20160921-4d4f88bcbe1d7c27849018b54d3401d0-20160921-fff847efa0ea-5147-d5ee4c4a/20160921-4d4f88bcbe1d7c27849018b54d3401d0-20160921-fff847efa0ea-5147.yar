rule _20160921_4d4f88bcbe1d7c27849018b54d3401d0_20160921_fff847efa0ea_5147 {
  meta:
    description = "datamaliciousorder - from files 20160921_4d4f88bcbe1d7c27849018b54d3401d0.js, 20160921_fff847efa0eaa326a0aad4d2fc81d41e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c037da0756f2e03c3daf2ada4f7a359fd0381e67b8eccb57785222e669ac983"
    hash2       = "93f868a10878cb41f305e28c8802778903c99b84a1bc0647a0c2c78fd6310577"

  strings:
    $s1 = "ction f000(){return \"TRc\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"OMd\";})(),(function f000(){retu" ascii
    $s2 = "{return \"Km\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(" ascii
    $s3 = "n\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"BQb\";})(),(function " ascii
    $s4 = "return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})()" ascii
    $s5 = "l\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"UEg\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
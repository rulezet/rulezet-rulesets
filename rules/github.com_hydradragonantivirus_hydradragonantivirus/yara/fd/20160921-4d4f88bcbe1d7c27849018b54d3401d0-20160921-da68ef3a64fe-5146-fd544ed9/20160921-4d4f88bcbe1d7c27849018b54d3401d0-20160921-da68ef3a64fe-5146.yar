rule _20160921_4d4f88bcbe1d7c27849018b54d3401d0_20160921_da68ef3a64fe_5146 {
  meta:
    description = "datamaliciousorder - from files 20160921_4d4f88bcbe1d7c27849018b54d3401d0.js, 20160921_da68ef3a64fe9761a5f4505bcaef8f82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c037da0756f2e03c3daf2ada4f7a359fd0381e67b8eccb57785222e669ac983"
    hash2       = "cecd93896e2d90bed54f31f9e387b5dcec7c277d5e455e561112b07c63d26ed5"

  strings:
    $s1 = ",(function f000(){return \"RPt\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KXg\";})(),(function f000(){" ascii
    $s2 = "rn \"Qz\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s3 = "return \"ZFe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qa\";})()" ascii
    $s4 = " \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mc\";})(),(func" ascii
    $s5 = "on f000(){return \"ZFe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"XTn\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
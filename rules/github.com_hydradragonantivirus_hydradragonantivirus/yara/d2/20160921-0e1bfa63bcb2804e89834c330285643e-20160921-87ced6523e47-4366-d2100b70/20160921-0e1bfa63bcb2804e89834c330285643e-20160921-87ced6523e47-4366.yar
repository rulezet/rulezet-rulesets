rule _20160921_0e1bfa63bcb2804e89834c330285643e_20160921_87ced6523e47_4366 {
  meta:
    description = "datamaliciousorder - from files 20160921_0e1bfa63bcb2804e89834c330285643e.js, 20160921_87ced6523e47b3b752b2353107bc989a.js, 20160921_945a46518061bd8e157aed251e0ffa9e.js, 20160921_ad1fccc6910bd9c4a47aa9bd3e9239da.js, 20160921_e39622eeb1da8fbbf03ca86989251a47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d58b57cb825244d35e22402fcf08c9ababcc51eb72a7913c47dbb2143171df32"
    hash2       = "46c521beb23d37cfa4d60cfcab38c941734971fe3102123b7e4c2813544d39b6"
    hash3       = "cc3d236edb3b45a767b438fa21243a07176d6f5def724e03e45aca76b3127054"
    hash4       = "a49fc1cb85eaa58b7c63197e9fd25224f63dcb6c86b906933f698898634ead3e"
    hash5       = "e0b1660f1c95284f1a0f8062a1f16e26aa3d58e3fa4cf47fc04824d02b754a56"

  strings:
    $s1 = "\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Et\";})(),(function f" ascii
    $s2 = ";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function fu" ascii
    $s3 = "t\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function" ascii
    $s4 = ")(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Sx\";})(),(function fuck()" ascii
    $s5 = "),(function fuck(){return \"Et\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
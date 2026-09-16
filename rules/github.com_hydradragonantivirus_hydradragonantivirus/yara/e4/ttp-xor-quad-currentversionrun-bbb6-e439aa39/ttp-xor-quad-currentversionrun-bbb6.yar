rule TTP_XOR_QUAD_CurrentVersionRun_bbb6 {
  strings:
    $key_bbb6 = { e8 d9 [2] cc d7 [2] e7 fb [2] c9 d9 [2] dd c2 [2] d2 d8 [2] cc c5 [2] ce c4 [2] d5 c2 [2] c9 c5 [2] d5 ea }

  condition:
    any of them
}
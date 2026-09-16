rule TTP_XOR_QUAD_CurrentVersionRun_bbb7 {
  strings:
    $key_bbb7 = { e8 d8 [2] cc d6 [2] e7 fa [2] c9 d8 [2] dd c3 [2] d2 d9 [2] cc c4 [2] ce c5 [2] d5 c3 [2] c9 c4 [2] d5 eb }

  condition:
    any of them
}
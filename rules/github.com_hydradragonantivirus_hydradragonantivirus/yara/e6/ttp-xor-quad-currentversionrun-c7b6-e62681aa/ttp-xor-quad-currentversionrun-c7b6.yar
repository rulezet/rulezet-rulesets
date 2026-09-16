rule TTP_XOR_QUAD_CurrentVersionRun_c7b6 {
  strings:
    $key_c7b6 = { 94 d9 [2] b0 d7 [2] 9b fb [2] b5 d9 [2] a1 c2 [2] ae d8 [2] b0 c5 [2] b2 c4 [2] a9 c2 [2] b5 c5 [2] a9 ea }

  condition:
    any of them
}
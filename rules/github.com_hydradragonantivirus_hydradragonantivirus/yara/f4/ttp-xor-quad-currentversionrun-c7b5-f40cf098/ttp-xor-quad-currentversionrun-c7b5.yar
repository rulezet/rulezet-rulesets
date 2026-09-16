rule TTP_XOR_QUAD_CurrentVersionRun_c7b5 {
  strings:
    $key_c7b5 = { 94 da [2] b0 d4 [2] 9b f8 [2] b5 da [2] a1 c1 [2] ae db [2] b0 c6 [2] b2 c7 [2] a9 c1 [2] b5 c6 [2] a9 e9 }

  condition:
    any of them
}
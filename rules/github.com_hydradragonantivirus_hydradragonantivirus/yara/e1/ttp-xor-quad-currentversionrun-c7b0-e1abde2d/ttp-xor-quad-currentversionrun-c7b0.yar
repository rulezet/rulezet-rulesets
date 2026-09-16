rule TTP_XOR_QUAD_CurrentVersionRun_c7b0 {
  strings:
    $key_c7b0 = { 94 df [2] b0 d1 [2] 9b fd [2] b5 df [2] a1 c4 [2] ae de [2] b0 c3 [2] b2 c2 [2] a9 c4 [2] b5 c3 [2] a9 ec }

  condition:
    any of them
}
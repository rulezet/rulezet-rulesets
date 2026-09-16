rule TTP_XOR_QUAD_CurrentVersionRun_c6b0 {
  strings:
    $key_c6b0 = { 95 df [2] b1 d1 [2] 9a fd [2] b4 df [2] a0 c4 [2] af de [2] b1 c3 [2] b3 c2 [2] a8 c4 [2] b4 c3 [2] a8 ec }

  condition:
    any of them
}
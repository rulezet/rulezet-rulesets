rule TTP_XOR_QUAD_CurrentVersionRun_f1b0 {
  strings:
    $key_f1b0 = { a2 df [2] 86 d1 [2] ad fd [2] 83 df [2] 97 c4 [2] 98 de [2] 86 c3 [2] 84 c2 [2] 9f c4 [2] 83 c3 [2] 9f ec }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_0bb0 {
  strings:
    $key_0bb0 = { 58 df [2] 7c d1 [2] 57 fd [2] 79 df [2] 6d c4 [2] 62 de [2] 7c c3 [2] 7e c2 [2] 65 c4 [2] 79 c3 [2] 65 ec }

  condition:
    any of them
}
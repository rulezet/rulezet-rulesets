rule TTP_XOR_QUAD_CurrentVersionRun_08b0 {
  strings:
    $key_08b0 = { 5b df [2] 7f d1 [2] 54 fd [2] 7a df [2] 6e c4 [2] 61 de [2] 7f c3 [2] 7d c2 [2] 66 c4 [2] 7a c3 [2] 66 ec }

  condition:
    any of them
}
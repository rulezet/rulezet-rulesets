rule TTP_XOR_QUAD_CurrentVersionRun_f8b0 {
  strings:
    $key_f8b0 = { ab df [2] 8f d1 [2] a4 fd [2] 8a df [2] 9e c4 [2] 91 de [2] 8f c3 [2] 8d c2 [2] 96 c4 [2] 8a c3 [2] 96 ec }

  condition:
    any of them
}
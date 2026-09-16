rule TTP_XOR_QUAD_CurrentVersionRun_18b0 {
  strings:
    $key_18b0 = { 4b df [2] 6f d1 [2] 44 fd [2] 6a df [2] 7e c4 [2] 71 de [2] 6f c3 [2] 6d c2 [2] 76 c4 [2] 6a c3 [2] 76 ec }

  condition:
    any of them
}
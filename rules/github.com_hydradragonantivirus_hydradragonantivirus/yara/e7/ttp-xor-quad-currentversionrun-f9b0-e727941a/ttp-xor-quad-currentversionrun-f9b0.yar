rule TTP_XOR_QUAD_CurrentVersionRun_f9b0 {
  strings:
    $key_f9b0 = { aa df [2] 8e d1 [2] a5 fd [2] 8b df [2] 9f c4 [2] 90 de [2] 8e c3 [2] 8c c2 [2] 97 c4 [2] 8b c3 [2] 97 ec }

  condition:
    any of them
}
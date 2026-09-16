rule TTP_XOR_QUAD_CurrentVersionRun_1cb0 {
  strings:
    $key_1cb0 = { 4f df [2] 6b d1 [2] 40 fd [2] 6e df [2] 7a c4 [2] 75 de [2] 6b c3 [2] 69 c2 [2] 72 c4 [2] 6e c3 [2] 72 ec }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_4cb0 {
  strings:
    $key_4cb0 = { 1f df [2] 3b d1 [2] 10 fd [2] 3e df [2] 2a c4 [2] 25 de [2] 3b c3 [2] 39 c2 [2] 22 c4 [2] 3e c3 [2] 22 ec }

  condition:
    any of them
}
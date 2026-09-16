rule TTP_XOR_QUAD_CurrentVersionRun_e7b0 {
  strings:
    $key_e7b0 = { b4 df [2] 90 d1 [2] bb fd [2] 95 df [2] 81 c4 [2] 8e de [2] 90 c3 [2] 92 c2 [2] 89 c4 [2] 95 c3 [2] 89 ec }

  condition:
    any of them
}
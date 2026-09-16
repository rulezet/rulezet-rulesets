rule TTP_XOR_QUAD_CurrentVersionRun_7db0 {
  strings:
    $key_7db0 = { 2e df [2] 0a d1 [2] 21 fd [2] 0f df [2] 1b c4 [2] 14 de [2] 0a c3 [2] 08 c2 [2] 13 c4 [2] 0f c3 [2] 13 ec }

  condition:
    any of them
}
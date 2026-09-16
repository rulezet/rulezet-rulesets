rule TTP_XOR_QUAD_CurrentVersionRun_7eb0 {
  strings:
    $key_7eb0 = { 2d df [2] 09 d1 [2] 22 fd [2] 0c df [2] 18 c4 [2] 17 de [2] 09 c3 [2] 0b c2 [2] 10 c4 [2] 0c c3 [2] 10 ec }

  condition:
    any of them
}
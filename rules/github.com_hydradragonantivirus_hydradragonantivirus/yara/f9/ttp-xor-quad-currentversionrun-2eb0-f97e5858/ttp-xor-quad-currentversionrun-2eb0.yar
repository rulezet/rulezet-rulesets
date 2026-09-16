rule TTP_XOR_QUAD_CurrentVersionRun_2eb0 {
  strings:
    $key_2eb0 = { 7d df [2] 59 d1 [2] 72 fd [2] 5c df [2] 48 c4 [2] 47 de [2] 59 c3 [2] 5b c2 [2] 40 c4 [2] 5c c3 [2] 40 ec }

  condition:
    any of them
}
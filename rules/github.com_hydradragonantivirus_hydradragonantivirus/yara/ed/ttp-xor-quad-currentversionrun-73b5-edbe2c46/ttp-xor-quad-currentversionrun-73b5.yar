rule TTP_XOR_QUAD_CurrentVersionRun_73b5 {
  strings:
    $key_73b5 = { 20 da [2] 04 d4 [2] 2f f8 [2] 01 da [2] 15 c1 [2] 1a db [2] 04 c6 [2] 06 c7 [2] 1d c1 [2] 01 c6 [2] 1d e9 }

  condition:
    any of them
}
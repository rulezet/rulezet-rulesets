rule TTP_XOR_QUAD_CurrentVersionRun_2596 {
  strings:
    $key_2596 = { 76 f9 [2] 52 f7 [2] 79 db [2] 57 f9 [2] 43 e2 [2] 4c f8 [2] 52 e5 [2] 50 e4 [2] 4b e2 [2] 57 e5 [2] 4b ca }

  condition:
    any of them
}
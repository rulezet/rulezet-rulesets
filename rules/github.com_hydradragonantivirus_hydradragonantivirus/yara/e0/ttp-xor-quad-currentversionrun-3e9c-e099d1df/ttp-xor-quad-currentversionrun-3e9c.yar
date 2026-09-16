rule TTP_XOR_QUAD_CurrentVersionRun_3e9c {
  strings:
    $key_3e9c = { 6d f3 [2] 49 fd [2] 62 d1 [2] 4c f3 [2] 58 e8 [2] 57 f2 [2] 49 ef [2] 4b ee [2] 50 e8 [2] 4c ef [2] 50 c0 }

  condition:
    any of them
}
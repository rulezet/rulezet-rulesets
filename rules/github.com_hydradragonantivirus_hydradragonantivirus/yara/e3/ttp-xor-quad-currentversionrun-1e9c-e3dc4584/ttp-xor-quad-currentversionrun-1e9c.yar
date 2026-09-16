rule TTP_XOR_QUAD_CurrentVersionRun_1e9c {
  strings:
    $key_1e9c = { 4d f3 [2] 69 fd [2] 42 d1 [2] 6c f3 [2] 78 e8 [2] 77 f2 [2] 69 ef [2] 6b ee [2] 70 e8 [2] 6c ef [2] 70 c0 }

  condition:
    any of them
}
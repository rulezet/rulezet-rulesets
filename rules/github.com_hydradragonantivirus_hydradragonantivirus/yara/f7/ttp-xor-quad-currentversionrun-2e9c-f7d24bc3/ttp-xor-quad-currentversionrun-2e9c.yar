rule TTP_XOR_QUAD_CurrentVersionRun_2e9c {
  strings:
    $key_2e9c = { 7d f3 [2] 59 fd [2] 72 d1 [2] 5c f3 [2] 48 e8 [2] 47 f2 [2] 59 ef [2] 5b ee [2] 40 e8 [2] 5c ef [2] 40 c0 }

  condition:
    any of them
}
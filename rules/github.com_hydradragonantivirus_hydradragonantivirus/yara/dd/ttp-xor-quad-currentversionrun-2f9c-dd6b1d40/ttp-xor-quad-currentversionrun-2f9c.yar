rule TTP_XOR_QUAD_CurrentVersionRun_2f9c {
  strings:
    $key_2f9c = { 7c f3 [2] 58 fd [2] 73 d1 [2] 5d f3 [2] 49 e8 [2] 46 f2 [2] 58 ef [2] 5a ee [2] 41 e8 [2] 5d ef [2] 41 c0 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_a39b {
  strings:
    $key_a39b = { f0 f4 [2] d4 fa [2] ff d6 [2] d1 f4 [2] c5 ef [2] ca f5 [2] d4 e8 [2] d6 e9 [2] cd ef [2] d1 e8 [2] cd c7 }

  condition:
    any of them
}
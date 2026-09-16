rule TTP_XOR_QUAD_CurrentVersionRun_a39a {
  strings:
    $key_a39a = { f0 f5 [2] d4 fb [2] ff d7 [2] d1 f5 [2] c5 ee [2] ca f4 [2] d4 e9 [2] d6 e8 [2] cd ee [2] d1 e9 [2] cd c6 }

  condition:
    any of them
}
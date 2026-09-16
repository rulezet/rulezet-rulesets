rule TTP_XOR_QUAD_CurrentVersionRun_bfaf {
  strings:
    $key_bfaf = { ec c0 [2] c8 ce [2] e3 e2 [2] cd c0 [2] d9 db [2] d6 c1 [2] c8 dc [2] ca dd [2] d1 db [2] cd dc [2] d1 f3 }

  condition:
    any of them
}
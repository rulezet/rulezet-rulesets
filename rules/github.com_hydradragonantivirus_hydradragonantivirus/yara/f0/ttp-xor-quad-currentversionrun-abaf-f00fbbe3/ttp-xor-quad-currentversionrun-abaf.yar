rule TTP_XOR_QUAD_CurrentVersionRun_abaf {
  strings:
    $key_abaf = { f8 c0 [2] dc ce [2] f7 e2 [2] d9 c0 [2] cd db [2] c2 c1 [2] dc dc [2] de dd [2] c5 db [2] d9 dc [2] c5 f3 }

  condition:
    any of them
}
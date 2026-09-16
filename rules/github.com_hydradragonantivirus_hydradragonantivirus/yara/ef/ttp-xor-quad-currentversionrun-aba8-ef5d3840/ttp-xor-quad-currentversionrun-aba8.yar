rule TTP_XOR_QUAD_CurrentVersionRun_aba8 {
  strings:
    $key_aba8 = { f8 c7 [2] dc c9 [2] f7 e5 [2] d9 c7 [2] cd dc [2] c2 c6 [2] dc db [2] de da [2] c5 dc [2] d9 db [2] c5 f4 }

  condition:
    any of them
}
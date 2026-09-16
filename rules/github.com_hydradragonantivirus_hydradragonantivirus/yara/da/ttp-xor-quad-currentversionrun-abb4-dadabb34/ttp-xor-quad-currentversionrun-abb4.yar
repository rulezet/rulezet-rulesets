rule TTP_XOR_QUAD_CurrentVersionRun_abb4 {
  strings:
    $key_abb4 = { f8 db [2] dc d5 [2] f7 f9 [2] d9 db [2] cd c0 [2] c2 da [2] dc c7 [2] de c6 [2] c5 c0 [2] d9 c7 [2] c5 e8 }

  condition:
    any of them
}
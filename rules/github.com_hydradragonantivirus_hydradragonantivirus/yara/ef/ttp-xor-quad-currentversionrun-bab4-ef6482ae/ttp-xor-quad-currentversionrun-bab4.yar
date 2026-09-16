rule TTP_XOR_QUAD_CurrentVersionRun_bab4 {
  strings:
    $key_bab4 = { e9 db [2] cd d5 [2] e6 f9 [2] c8 db [2] dc c0 [2] d3 da [2] cd c7 [2] cf c6 [2] d4 c0 [2] c8 c7 [2] d4 e8 }

  condition:
    any of them
}
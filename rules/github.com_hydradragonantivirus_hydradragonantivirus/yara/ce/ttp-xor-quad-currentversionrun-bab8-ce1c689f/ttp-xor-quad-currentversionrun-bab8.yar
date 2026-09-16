rule TTP_XOR_QUAD_CurrentVersionRun_bab8 {
  strings:
    $key_bab8 = { e9 d7 [2] cd d9 [2] e6 f5 [2] c8 d7 [2] dc cc [2] d3 d6 [2] cd cb [2] cf ca [2] d4 cc [2] c8 cb [2] d4 e4 }

  condition:
    any of them
}
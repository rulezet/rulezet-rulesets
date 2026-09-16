rule TTP_XOR_QUAD_CurrentVersionRun_baa4 {
  strings:
    $key_baa4 = { e9 cb [2] cd c5 [2] e6 e9 [2] c8 cb [2] dc d0 [2] d3 ca [2] cd d7 [2] cf d6 [2] d4 d0 [2] c8 d7 [2] d4 f8 }

  condition:
    any of them
}
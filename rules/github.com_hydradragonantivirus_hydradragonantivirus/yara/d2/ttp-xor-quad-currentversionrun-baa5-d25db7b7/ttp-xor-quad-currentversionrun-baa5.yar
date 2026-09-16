rule TTP_XOR_QUAD_CurrentVersionRun_baa5 {
  strings:
    $key_baa5 = { e9 ca [2] cd c4 [2] e6 e8 [2] c8 ca [2] dc d1 [2] d3 cb [2] cd d6 [2] cf d7 [2] d4 d1 [2] c8 d6 [2] d4 f9 }

  condition:
    any of them
}
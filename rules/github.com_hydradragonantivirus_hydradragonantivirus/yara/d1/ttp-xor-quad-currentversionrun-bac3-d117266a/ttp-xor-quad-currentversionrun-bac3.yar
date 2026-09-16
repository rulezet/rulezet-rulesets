rule TTP_XOR_QUAD_CurrentVersionRun_bac3 {
  strings:
    $key_bac3 = { e9 ac [2] cd a2 [2] e6 8e [2] c8 ac [2] dc b7 [2] d3 ad [2] cd b0 [2] cf b1 [2] d4 b7 [2] c8 b0 [2] d4 9f }

  condition:
    any of them
}
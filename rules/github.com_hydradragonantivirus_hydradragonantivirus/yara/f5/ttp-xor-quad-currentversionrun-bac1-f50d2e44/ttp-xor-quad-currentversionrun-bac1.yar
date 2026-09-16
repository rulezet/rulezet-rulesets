rule TTP_XOR_QUAD_CurrentVersionRun_bac1 {
  strings:
    $key_bac1 = { e9 ae [2] cd a0 [2] e6 8c [2] c8 ae [2] dc b5 [2] d3 af [2] cd b2 [2] cf b3 [2] d4 b5 [2] c8 b2 [2] d4 9d }

  condition:
    any of them
}
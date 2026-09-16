rule TTP_XOR_QUAD_CurrentVersionRun_bfd7 {
  strings:
    $key_bfd7 = { ec b8 [2] c8 b6 [2] e3 9a [2] cd b8 [2] d9 a3 [2] d6 b9 [2] c8 a4 [2] ca a5 [2] d1 a3 [2] cd a4 [2] d1 8b }

  condition:
    any of them
}
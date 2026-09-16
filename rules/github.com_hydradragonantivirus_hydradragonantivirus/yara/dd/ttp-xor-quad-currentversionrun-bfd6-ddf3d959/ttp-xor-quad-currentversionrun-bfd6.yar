rule TTP_XOR_QUAD_CurrentVersionRun_bfd6 {
  strings:
    $key_bfd6 = { ec b9 [2] c8 b7 [2] e3 9b [2] cd b9 [2] d9 a2 [2] d6 b8 [2] c8 a5 [2] ca a4 [2] d1 a2 [2] cd a5 [2] d1 8a }

  condition:
    any of them
}
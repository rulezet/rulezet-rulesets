rule TTP_XOR_QUAD_CurrentVersionRun_a3b6 {
  strings:
    $key_a3b6 = { f0 d9 [2] d4 d7 [2] ff fb [2] d1 d9 [2] c5 c2 [2] ca d8 [2] d4 c5 [2] d6 c4 [2] cd c2 [2] d1 c5 [2] cd ea }

  condition:
    any of them
}
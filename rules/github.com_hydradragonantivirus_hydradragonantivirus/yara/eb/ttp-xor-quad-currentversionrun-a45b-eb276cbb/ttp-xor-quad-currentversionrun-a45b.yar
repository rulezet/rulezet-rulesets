rule TTP_XOR_QUAD_CurrentVersionRun_a45b {
  strings:
    $key_a45b = { f7 34 [2] d3 3a [2] f8 16 [2] d6 34 [2] c2 2f [2] cd 35 [2] d3 28 [2] d1 29 [2] ca 2f [2] d6 28 [2] ca 07 }

  condition:
    any of them
}
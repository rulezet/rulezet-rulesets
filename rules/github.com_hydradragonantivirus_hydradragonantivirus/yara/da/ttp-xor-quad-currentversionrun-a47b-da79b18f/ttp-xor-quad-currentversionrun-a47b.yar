rule TTP_XOR_QUAD_CurrentVersionRun_a47b {
  strings:
    $key_a47b = { f7 14 [2] d3 1a [2] f8 36 [2] d6 14 [2] c2 0f [2] cd 15 [2] d3 08 [2] d1 09 [2] ca 0f [2] d6 08 [2] ca 27 }

  condition:
    any of them
}
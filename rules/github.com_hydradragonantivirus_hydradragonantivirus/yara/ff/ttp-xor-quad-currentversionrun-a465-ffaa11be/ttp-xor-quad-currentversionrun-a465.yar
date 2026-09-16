rule TTP_XOR_QUAD_CurrentVersionRun_a465 {
  strings:
    $key_a465 = { f7 0a [2] d3 04 [2] f8 28 [2] d6 0a [2] c2 11 [2] cd 0b [2] d3 16 [2] d1 17 [2] ca 11 [2] d6 16 [2] ca 39 }

  condition:
    any of them
}
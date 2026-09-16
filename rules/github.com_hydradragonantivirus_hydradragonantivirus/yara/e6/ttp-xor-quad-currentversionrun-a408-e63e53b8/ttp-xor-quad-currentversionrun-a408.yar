rule TTP_XOR_QUAD_CurrentVersionRun_a408 {
  strings:
    $key_a408 = { f7 67 [2] d3 69 [2] f8 45 [2] d6 67 [2] c2 7c [2] cd 66 [2] d3 7b [2] d1 7a [2] ca 7c [2] d6 7b [2] ca 54 }

  condition:
    any of them
}
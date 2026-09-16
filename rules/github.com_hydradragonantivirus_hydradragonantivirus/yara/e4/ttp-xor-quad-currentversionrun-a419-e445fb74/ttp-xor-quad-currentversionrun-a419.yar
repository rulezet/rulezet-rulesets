rule TTP_XOR_QUAD_CurrentVersionRun_a419 {
  strings:
    $key_a419 = { f7 76 [2] d3 78 [2] f8 54 [2] d6 76 [2] c2 6d [2] cd 77 [2] d3 6a [2] d1 6b [2] ca 6d [2] d6 6a [2] ca 45 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_a414 {
  strings:
    $key_a414 = { f7 7b [2] d3 75 [2] f8 59 [2] d6 7b [2] c2 60 [2] cd 7a [2] d3 67 [2] d1 66 [2] ca 60 [2] d6 67 [2] ca 48 }

  condition:
    any of them
}
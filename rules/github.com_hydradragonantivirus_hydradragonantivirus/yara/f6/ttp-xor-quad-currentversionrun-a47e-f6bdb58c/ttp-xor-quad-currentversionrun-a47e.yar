rule TTP_XOR_QUAD_CurrentVersionRun_a47e {
  strings:
    $key_a47e = { f7 11 [2] d3 1f [2] f8 33 [2] d6 11 [2] c2 0a [2] cd 10 [2] d3 0d [2] d1 0c [2] ca 0a [2] d6 0d [2] ca 22 }

  condition:
    any of them
}
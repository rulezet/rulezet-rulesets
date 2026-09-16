rule TTP_XOR_QUAD_CurrentVersionRun_a450 {
  strings:
    $key_a450 = { f7 3f [2] d3 31 [2] f8 1d [2] d6 3f [2] c2 24 [2] cd 3e [2] d3 23 [2] d1 22 [2] ca 24 [2] d6 23 [2] ca 0c }

  condition:
    any of them
}
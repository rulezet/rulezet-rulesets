rule TTP_XOR_QUAD_CurrentVersionRun_a46a {
  strings:
    $key_a46a = { f7 05 [2] d3 0b [2] f8 27 [2] d6 05 [2] c2 1e [2] cd 04 [2] d3 19 [2] d1 18 [2] ca 1e [2] d6 19 [2] ca 36 }

  condition:
    any of them
}
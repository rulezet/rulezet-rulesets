rule TTP_XOR_QUAD_CurrentVersionRun_a4ec {
  strings:
    $key_a4ec = { f7 83 [2] d3 8d [2] f8 a1 [2] d6 83 [2] c2 98 [2] cd 82 [2] d3 9f [2] d1 9e [2] ca 98 [2] d6 9f [2] ca b0 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_a45f {
  strings:
    $key_a45f = { f7 30 [2] d3 3e [2] f8 12 [2] d6 30 [2] c2 2b [2] cd 31 [2] d3 2c [2] d1 2d [2] ca 2b [2] d6 2c [2] ca 03 }

  condition:
    any of them
}
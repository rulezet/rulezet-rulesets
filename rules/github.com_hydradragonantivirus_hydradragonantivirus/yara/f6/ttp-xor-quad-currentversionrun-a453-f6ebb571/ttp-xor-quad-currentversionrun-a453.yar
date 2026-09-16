rule TTP_XOR_QUAD_CurrentVersionRun_a453 {
  strings:
    $key_a453 = { f7 3c [2] d3 32 [2] f8 1e [2] d6 3c [2] c2 27 [2] cd 3d [2] d3 20 [2] d1 21 [2] ca 27 [2] d6 20 [2] ca 0f }

  condition:
    any of them
}
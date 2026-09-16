rule TTP_XOR_QUAD_CurrentVersionRun_ab53 {
  strings:
    $key_ab53 = { f8 3c [2] dc 32 [2] f7 1e [2] d9 3c [2] cd 27 [2] c2 3d [2] dc 20 [2] de 21 [2] c5 27 [2] d9 20 [2] c5 0f }

  condition:
    any of them
}
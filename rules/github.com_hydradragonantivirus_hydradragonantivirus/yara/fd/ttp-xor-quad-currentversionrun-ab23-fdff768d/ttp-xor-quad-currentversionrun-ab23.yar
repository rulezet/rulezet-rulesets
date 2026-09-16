rule TTP_XOR_QUAD_CurrentVersionRun_ab23 {
  strings:
    $key_ab23 = { f8 4c [2] dc 42 [2] f7 6e [2] d9 4c [2] cd 57 [2] c2 4d [2] dc 50 [2] de 51 [2] c5 57 [2] d9 50 [2] c5 7f }

  condition:
    any of them
}
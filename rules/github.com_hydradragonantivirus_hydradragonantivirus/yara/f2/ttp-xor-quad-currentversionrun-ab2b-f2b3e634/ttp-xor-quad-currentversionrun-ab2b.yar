rule TTP_XOR_QUAD_CurrentVersionRun_ab2b {
  strings:
    $key_ab2b = { f8 44 [2] dc 4a [2] f7 66 [2] d9 44 [2] cd 5f [2] c2 45 [2] dc 58 [2] de 59 [2] c5 5f [2] d9 58 [2] c5 77 }

  condition:
    any of them
}
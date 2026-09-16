rule TTP_XOR_QUAD_CurrentVersionRun_abf4 {
  strings:
    $key_abf4 = { f8 9b [2] dc 95 [2] f7 b9 [2] d9 9b [2] cd 80 [2] c2 9a [2] dc 87 [2] de 86 [2] c5 80 [2] d9 87 [2] c5 a8 }

  condition:
    any of them
}
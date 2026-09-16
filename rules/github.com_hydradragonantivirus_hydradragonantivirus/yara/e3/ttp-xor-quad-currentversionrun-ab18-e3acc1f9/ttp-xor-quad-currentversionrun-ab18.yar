rule TTP_XOR_QUAD_CurrentVersionRun_ab18 {
  strings:
    $key_ab18 = { f8 77 [2] dc 79 [2] f7 55 [2] d9 77 [2] cd 6c [2] c2 76 [2] dc 6b [2] de 6a [2] c5 6c [2] d9 6b [2] c5 44 }

  condition:
    any of them
}
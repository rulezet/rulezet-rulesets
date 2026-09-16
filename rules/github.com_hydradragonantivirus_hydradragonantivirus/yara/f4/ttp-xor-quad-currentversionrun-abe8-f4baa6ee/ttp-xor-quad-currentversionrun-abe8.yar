rule TTP_XOR_QUAD_CurrentVersionRun_abe8 {
  strings:
    $key_abe8 = { f8 87 [2] dc 89 [2] f7 a5 [2] d9 87 [2] cd 9c [2] c2 86 [2] dc 9b [2] de 9a [2] c5 9c [2] d9 9b [2] c5 b4 }

  condition:
    any of them
}
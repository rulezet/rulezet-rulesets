rule TTP_XOR_QUAD_CurrentVersionRun_ab04 {
  strings:
    $key_ab04 = { f8 6b [2] dc 65 [2] f7 49 [2] d9 6b [2] cd 70 [2] c2 6a [2] dc 77 [2] de 76 [2] c5 70 [2] d9 77 [2] c5 58 }

  condition:
    any of them
}
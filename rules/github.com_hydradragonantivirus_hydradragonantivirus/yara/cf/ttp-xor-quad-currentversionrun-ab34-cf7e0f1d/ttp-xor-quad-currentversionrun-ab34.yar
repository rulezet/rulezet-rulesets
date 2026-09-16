rule TTP_XOR_QUAD_CurrentVersionRun_ab34 {
  strings:
    $key_ab34 = { f8 5b [2] dc 55 [2] f7 79 [2] d9 5b [2] cd 40 [2] c2 5a [2] dc 47 [2] de 46 [2] c5 40 [2] d9 47 [2] c5 68 }

  condition:
    any of them
}
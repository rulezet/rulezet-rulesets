rule TTP_XOR_QUAD_CurrentVersionRun_abf8 {
  strings:
    $key_abf8 = { f8 97 [2] dc 99 [2] f7 b5 [2] d9 97 [2] cd 8c [2] c2 96 [2] dc 8b [2] de 8a [2] c5 8c [2] d9 8b [2] c5 a4 }

  condition:
    any of them
}
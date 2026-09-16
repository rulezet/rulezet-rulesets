rule TTP_XOR_QUAD_CurrentVersionRun_abe9 {
  strings:
    $key_abe9 = { f8 86 [2] dc 88 [2] f7 a4 [2] d9 86 [2] cd 9d [2] c2 87 [2] dc 9a [2] de 9b [2] c5 9d [2] d9 9a [2] c5 b5 }

  condition:
    any of them
}
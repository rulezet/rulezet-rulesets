rule TTP_XOR_QUAD_CurrentVersionRun_27f5 {
  strings:
    $key_27f5 = { 74 9a [2] 50 94 [2] 7b b8 [2] 55 9a [2] 41 81 [2] 4e 9b [2] 50 86 [2] 52 87 [2] 49 81 [2] 55 86 [2] 49 a9 }

  condition:
    any of them
}
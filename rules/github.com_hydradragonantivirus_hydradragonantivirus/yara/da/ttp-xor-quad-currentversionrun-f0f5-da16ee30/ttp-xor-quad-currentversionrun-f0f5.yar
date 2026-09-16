rule TTP_XOR_QUAD_CurrentVersionRun_f0f5 {
  strings:
    $key_f0f5 = { a3 9a [2] 87 94 [2] ac b8 [2] 82 9a [2] 96 81 [2] 99 9b [2] 87 86 [2] 85 87 [2] 9e 81 [2] 82 86 [2] 9e a9 }

  condition:
    any of them
}
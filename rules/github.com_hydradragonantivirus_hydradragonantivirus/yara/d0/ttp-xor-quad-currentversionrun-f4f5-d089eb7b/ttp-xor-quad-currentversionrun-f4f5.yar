rule TTP_XOR_QUAD_CurrentVersionRun_f4f5 {
  strings:
    $key_f4f5 = { a7 9a [2] 83 94 [2] a8 b8 [2] 86 9a [2] 92 81 [2] 9d 9b [2] 83 86 [2] 81 87 [2] 9a 81 [2] 86 86 [2] 9a a9 }

  condition:
    any of them
}
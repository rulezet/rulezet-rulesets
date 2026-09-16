rule TTP_XOR_QUAD_CurrentVersionRun_f5f4 {
  strings:
    $key_f5f4 = { a6 9b [2] 82 95 [2] a9 b9 [2] 87 9b [2] 93 80 [2] 9c 9a [2] 82 87 [2] 80 86 [2] 9b 80 [2] 87 87 [2] 9b a8 }

  condition:
    any of them
}
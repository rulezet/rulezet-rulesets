rule TTP_XOR_QUAD_CurrentVersionRun_f5f8 {
  strings:
    $key_f5f8 = { a6 97 [2] 82 99 [2] a9 b5 [2] 87 97 [2] 93 8c [2] 9c 96 [2] 82 8b [2] 80 8a [2] 9b 8c [2] 87 8b [2] 9b a4 }

  condition:
    any of them
}
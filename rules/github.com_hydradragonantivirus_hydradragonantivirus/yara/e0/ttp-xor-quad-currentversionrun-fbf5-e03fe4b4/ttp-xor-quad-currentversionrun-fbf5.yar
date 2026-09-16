rule TTP_XOR_QUAD_CurrentVersionRun_fbf5 {
  strings:
    $key_fbf5 = { a8 9a [2] 8c 94 [2] a7 b8 [2] 89 9a [2] 9d 81 [2] 92 9b [2] 8c 86 [2] 8e 87 [2] 95 81 [2] 89 86 [2] 95 a9 }

  condition:
    any of them
}
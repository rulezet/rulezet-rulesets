rule TTP_XOR_QUAD_CurrentVersionRun_f518 {
  strings:
    $key_f518 = { a6 77 [2] 82 79 [2] a9 55 [2] 87 77 [2] 93 6c [2] 9c 76 [2] 82 6b [2] 80 6a [2] 9b 6c [2] 87 6b [2] 9b 44 }

  condition:
    any of them
}
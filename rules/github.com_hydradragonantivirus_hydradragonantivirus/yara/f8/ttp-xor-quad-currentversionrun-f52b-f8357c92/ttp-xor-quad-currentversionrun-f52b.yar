rule TTP_XOR_QUAD_CurrentVersionRun_f52b {
  strings:
    $key_f52b = { a6 44 [2] 82 4a [2] a9 66 [2] 87 44 [2] 93 5f [2] 9c 45 [2] 82 58 [2] 80 59 [2] 9b 5f [2] 87 58 [2] 9b 77 }

  condition:
    any of them
}
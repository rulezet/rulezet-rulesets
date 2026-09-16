rule TTP_XOR_QUAD_CurrentVersionRun_f264 {
  strings:
    $key_f264 = { a1 0b [2] 85 05 [2] ae 29 [2] 80 0b [2] 94 10 [2] 9b 0a [2] 85 17 [2] 87 16 [2] 9c 10 [2] 80 17 [2] 9c 38 }

  condition:
    any of them
}
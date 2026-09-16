rule TTP_XOR_QUAD_CurrentVersionRun_f464 {
  strings:
    $key_f464 = { a7 0b [2] 83 05 [2] a8 29 [2] 86 0b [2] 92 10 [2] 9d 0a [2] 83 17 [2] 81 16 [2] 9a 10 [2] 86 17 [2] 9a 38 }

  condition:
    any of them
}
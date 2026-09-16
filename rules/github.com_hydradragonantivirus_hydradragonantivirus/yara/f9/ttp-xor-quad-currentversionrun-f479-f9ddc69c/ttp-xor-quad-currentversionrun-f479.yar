rule TTP_XOR_QUAD_CurrentVersionRun_f479 {
  strings:
    $key_f479 = { a7 16 [2] 83 18 [2] a8 34 [2] 86 16 [2] 92 0d [2] 9d 17 [2] 83 0a [2] 81 0b [2] 9a 0d [2] 86 0a [2] 9a 25 }

  condition:
    any of them
}
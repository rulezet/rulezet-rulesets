rule TTP_XOR_QUAD_CurrentVersionRun_1cf4 {
  strings:
    $key_1cf4 = { 4f 9b [2] 6b 95 [2] 40 b9 [2] 6e 9b [2] 7a 80 [2] 75 9a [2] 6b 87 [2] 69 86 [2] 72 80 [2] 6e 87 [2] 72 a8 }

  condition:
    any of them
}
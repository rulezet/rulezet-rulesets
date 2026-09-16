rule TTP_XOR_QUAD_CurrentVersionRun_f554 {
  strings:
    $key_f554 = { a6 3b [2] 82 35 [2] a9 19 [2] 87 3b [2] 93 20 [2] 9c 3a [2] 82 27 [2] 80 26 [2] 9b 20 [2] 87 27 [2] 9b 08 }

  condition:
    any of them
}
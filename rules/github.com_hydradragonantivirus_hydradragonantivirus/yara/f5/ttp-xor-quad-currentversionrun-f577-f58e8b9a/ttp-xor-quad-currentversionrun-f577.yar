rule TTP_XOR_QUAD_CurrentVersionRun_f577 {
  strings:
    $key_f577 = { a6 18 [2] 82 16 [2] a9 3a [2] 87 18 [2] 93 03 [2] 9c 19 [2] 82 04 [2] 80 05 [2] 9b 03 [2] 87 04 [2] 9b 2b }

  condition:
    any of them
}
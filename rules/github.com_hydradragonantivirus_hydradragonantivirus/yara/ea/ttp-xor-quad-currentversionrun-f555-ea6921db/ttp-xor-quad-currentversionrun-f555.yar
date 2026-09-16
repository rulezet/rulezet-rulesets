rule TTP_XOR_QUAD_CurrentVersionRun_f555 {
  strings:
    $key_f555 = { a6 3a [2] 82 34 [2] a9 18 [2] 87 3a [2] 93 21 [2] 9c 3b [2] 82 26 [2] 80 27 [2] 9b 21 [2] 87 26 [2] 9b 09 }

  condition:
    any of them
}
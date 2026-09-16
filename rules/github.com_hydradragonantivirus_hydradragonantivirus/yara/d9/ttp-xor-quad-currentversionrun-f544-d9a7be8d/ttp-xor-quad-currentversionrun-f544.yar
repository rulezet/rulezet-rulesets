rule TTP_XOR_QUAD_CurrentVersionRun_f544 {
  strings:
    $key_f544 = { a6 2b [2] 82 25 [2] a9 09 [2] 87 2b [2] 93 30 [2] 9c 2a [2] 82 37 [2] 80 36 [2] 9b 30 [2] 87 37 [2] 9b 18 }

  condition:
    any of them
}
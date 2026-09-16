rule TTP_XOR_QUAD_CurrentVersionRun_f55a {
  strings:
    $key_f55a = { a6 35 [2] 82 3b [2] a9 17 [2] 87 35 [2] 93 2e [2] 9c 34 [2] 82 29 [2] 80 28 [2] 9b 2e [2] 87 29 [2] 9b 06 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_f57a {
  strings:
    $key_f57a = { a6 15 [2] 82 1b [2] a9 37 [2] 87 15 [2] 93 0e [2] 9c 14 [2] 82 09 [2] 80 08 [2] 9b 0e [2] 87 09 [2] 9b 26 }

  condition:
    any of them
}
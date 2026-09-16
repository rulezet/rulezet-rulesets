rule TTP_XOR_QUAD_CurrentVersionRun_f550 {
  strings:
    $key_f550 = { a6 3f [2] 82 31 [2] a9 1d [2] 87 3f [2] 93 24 [2] 9c 3e [2] 82 23 [2] 80 22 [2] 9b 24 [2] 87 23 [2] 9b 0c }

  condition:
    any of them
}
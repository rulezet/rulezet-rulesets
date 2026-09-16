rule TTP_XOR_QUAD_CurrentVersionRun_f45a {
  strings:
    $key_f45a = { a7 35 [2] 83 3b [2] a8 17 [2] 86 35 [2] 92 2e [2] 9d 34 [2] 83 29 [2] 81 28 [2] 9a 2e [2] 86 29 [2] 9a 06 }

  condition:
    any of them
}
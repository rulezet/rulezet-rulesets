rule TTP_XOR_QUAD_CurrentVersionRun_f501 {
  strings:
    $key_f501 = { a6 6e [2] 82 60 [2] a9 4c [2] 87 6e [2] 93 75 [2] 9c 6f [2] 82 72 [2] 80 73 [2] 9b 75 [2] 87 72 [2] 9b 5d }

  condition:
    any of them
}
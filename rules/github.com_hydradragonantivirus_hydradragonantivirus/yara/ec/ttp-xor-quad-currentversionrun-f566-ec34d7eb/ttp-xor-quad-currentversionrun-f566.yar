rule TTP_XOR_QUAD_CurrentVersionRun_f566 {
  strings:
    $key_f566 = { a6 09 [2] 82 07 [2] a9 2b [2] 87 09 [2] 93 12 [2] 9c 08 [2] 82 15 [2] 80 14 [2] 9b 12 [2] 87 15 [2] 9b 3a }

  condition:
    any of them
}
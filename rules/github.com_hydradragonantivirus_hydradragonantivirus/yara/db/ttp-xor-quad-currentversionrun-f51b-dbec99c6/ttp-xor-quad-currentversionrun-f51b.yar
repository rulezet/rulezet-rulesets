rule TTP_XOR_QUAD_CurrentVersionRun_f51b {
  strings:
    $key_f51b = { a6 74 [2] 82 7a [2] a9 56 [2] 87 74 [2] 93 6f [2] 9c 75 [2] 82 68 [2] 80 69 [2] 9b 6f [2] 87 68 [2] 9b 47 }

  condition:
    any of them
}
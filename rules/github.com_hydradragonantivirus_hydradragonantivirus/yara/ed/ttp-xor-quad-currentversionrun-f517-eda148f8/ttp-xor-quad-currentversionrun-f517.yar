rule TTP_XOR_QUAD_CurrentVersionRun_f517 {
  strings:
    $key_f517 = { a6 78 [2] 82 76 [2] a9 5a [2] 87 78 [2] 93 63 [2] 9c 79 [2] 82 64 [2] 80 65 [2] 9b 63 [2] 87 64 [2] 9b 4b }

  condition:
    any of them
}
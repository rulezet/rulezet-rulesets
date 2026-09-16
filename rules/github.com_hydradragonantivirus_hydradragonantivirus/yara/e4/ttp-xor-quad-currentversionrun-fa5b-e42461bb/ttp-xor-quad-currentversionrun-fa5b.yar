rule TTP_XOR_QUAD_CurrentVersionRun_fa5b {
  strings:
    $key_fa5b = { a9 34 [2] 8d 3a [2] a6 16 [2] 88 34 [2] 9c 2f [2] 93 35 [2] 8d 28 [2] 8f 29 [2] 94 2f [2] 88 28 [2] 94 07 }

  condition:
    any of them
}
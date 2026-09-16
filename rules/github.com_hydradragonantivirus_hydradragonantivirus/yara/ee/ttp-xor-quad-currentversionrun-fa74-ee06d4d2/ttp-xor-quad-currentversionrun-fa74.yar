rule TTP_XOR_QUAD_CurrentVersionRun_fa74 {
  strings:
    $key_fa74 = { a9 1b [2] 8d 15 [2] a6 39 [2] 88 1b [2] 9c 00 [2] 93 1a [2] 8d 07 [2] 8f 06 [2] 94 00 [2] 88 07 [2] 94 28 }

  condition:
    any of them
}
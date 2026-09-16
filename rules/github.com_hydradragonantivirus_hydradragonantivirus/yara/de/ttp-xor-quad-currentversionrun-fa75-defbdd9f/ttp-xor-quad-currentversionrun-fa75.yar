rule TTP_XOR_QUAD_CurrentVersionRun_fa75 {
  strings:
    $key_fa75 = { a9 1a [2] 8d 14 [2] a6 38 [2] 88 1a [2] 9c 01 [2] 93 1b [2] 8d 06 [2] 8f 07 [2] 94 01 [2] 88 06 [2] 94 29 }

  condition:
    any of them
}
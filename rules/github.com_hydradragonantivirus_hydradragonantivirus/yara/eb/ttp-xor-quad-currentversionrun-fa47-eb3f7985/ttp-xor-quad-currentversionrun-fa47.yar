rule TTP_XOR_QUAD_CurrentVersionRun_fa47 {
  strings:
    $key_fa47 = { a9 28 [2] 8d 26 [2] a6 0a [2] 88 28 [2] 9c 33 [2] 93 29 [2] 8d 34 [2] 8f 35 [2] 94 33 [2] 88 34 [2] 94 1b }

  condition:
    any of them
}
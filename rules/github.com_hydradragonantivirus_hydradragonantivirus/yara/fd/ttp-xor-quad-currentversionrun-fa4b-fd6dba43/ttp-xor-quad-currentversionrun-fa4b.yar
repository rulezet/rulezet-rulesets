rule TTP_XOR_QUAD_CurrentVersionRun_fa4b {
  strings:
    $key_fa4b = { a9 24 [2] 8d 2a [2] a6 06 [2] 88 24 [2] 9c 3f [2] 93 25 [2] 8d 38 [2] 8f 39 [2] 94 3f [2] 88 38 [2] 94 17 }

  condition:
    any of them
}
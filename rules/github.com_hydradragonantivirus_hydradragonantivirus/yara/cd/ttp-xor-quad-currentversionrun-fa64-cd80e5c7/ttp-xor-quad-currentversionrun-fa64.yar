rule TTP_XOR_QUAD_CurrentVersionRun_fa64 {
  strings:
    $key_fa64 = { a9 0b [2] 8d 05 [2] a6 29 [2] 88 0b [2] 9c 10 [2] 93 0a [2] 8d 17 [2] 8f 16 [2] 94 10 [2] 88 17 [2] 94 38 }

  condition:
    any of them
}
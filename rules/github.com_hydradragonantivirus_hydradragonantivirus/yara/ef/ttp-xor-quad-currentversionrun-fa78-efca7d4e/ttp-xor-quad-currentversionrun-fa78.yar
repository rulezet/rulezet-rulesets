rule TTP_XOR_QUAD_CurrentVersionRun_fa78 {
  strings:
    $key_fa78 = { a9 17 [2] 8d 19 [2] a6 35 [2] 88 17 [2] 9c 0c [2] 93 16 [2] 8d 0b [2] 8f 0a [2] 94 0c [2] 88 0b [2] 94 24 }

  condition:
    any of them
}
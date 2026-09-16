rule TTP_XOR_QUAD_CurrentVersionRun_fa39 {
  strings:
    $key_fa39 = { a9 56 [2] 8d 58 [2] a6 74 [2] 88 56 [2] 9c 4d [2] 93 57 [2] 8d 4a [2] 8f 4b [2] 94 4d [2] 88 4a [2] 94 65 }

  condition:
    any of them
}
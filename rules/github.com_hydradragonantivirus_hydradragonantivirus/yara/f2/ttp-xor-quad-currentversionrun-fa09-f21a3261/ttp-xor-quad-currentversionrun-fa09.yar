rule TTP_XOR_QUAD_CurrentVersionRun_fa09 {
  strings:
    $key_fa09 = { a9 66 [2] 8d 68 [2] a6 44 [2] 88 66 [2] 9c 7d [2] 93 67 [2] 8d 7a [2] 8f 7b [2] 94 7d [2] 88 7a [2] 94 55 }

  condition:
    any of them
}
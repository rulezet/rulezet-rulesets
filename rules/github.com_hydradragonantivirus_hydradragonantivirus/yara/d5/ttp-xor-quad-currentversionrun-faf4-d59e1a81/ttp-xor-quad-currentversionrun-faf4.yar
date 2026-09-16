rule TTP_XOR_QUAD_CurrentVersionRun_faf4 {
  strings:
    $key_faf4 = { a9 9b [2] 8d 95 [2] a6 b9 [2] 88 9b [2] 9c 80 [2] 93 9a [2] 8d 87 [2] 8f 86 [2] 94 80 [2] 88 87 [2] 94 a8 }

  condition:
    any of them
}
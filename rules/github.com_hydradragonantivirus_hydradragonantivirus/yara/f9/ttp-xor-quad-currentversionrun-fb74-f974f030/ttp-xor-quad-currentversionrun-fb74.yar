rule TTP_XOR_QUAD_CurrentVersionRun_fb74 {
  strings:
    $key_fb74 = { a8 1b [2] 8c 15 [2] a7 39 [2] 89 1b [2] 9d 00 [2] 92 1a [2] 8c 07 [2] 8e 06 [2] 95 00 [2] 89 07 [2] 95 28 }

  condition:
    any of them
}
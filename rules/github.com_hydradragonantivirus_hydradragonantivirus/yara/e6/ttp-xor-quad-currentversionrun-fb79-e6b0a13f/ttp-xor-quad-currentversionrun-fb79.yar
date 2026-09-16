rule TTP_XOR_QUAD_CurrentVersionRun_fb79 {
  strings:
    $key_fb79 = { a8 16 [2] 8c 18 [2] a7 34 [2] 89 16 [2] 9d 0d [2] 92 17 [2] 8c 0a [2] 8e 0b [2] 95 0d [2] 89 0a [2] 95 25 }

  condition:
    any of them
}
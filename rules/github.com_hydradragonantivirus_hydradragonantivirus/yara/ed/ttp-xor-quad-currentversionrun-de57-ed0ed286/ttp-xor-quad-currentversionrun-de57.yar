rule TTP_XOR_QUAD_CurrentVersionRun_de57 {
  strings:
    $key_de57 = { 8d 38 [2] a9 36 [2] 82 1a [2] ac 38 [2] b8 23 [2] b7 39 [2] a9 24 [2] ab 25 [2] b0 23 [2] ac 24 [2] b0 0b }

  condition:
    any of them
}
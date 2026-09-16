rule TTP_XOR_QUAD_CurrentVersionRun_de55 {
  strings:
    $key_de55 = { 8d 3a [2] a9 34 [2] 82 18 [2] ac 3a [2] b8 21 [2] b7 3b [2] a9 26 [2] ab 27 [2] b0 21 [2] ac 26 [2] b0 09 }

  condition:
    any of them
}
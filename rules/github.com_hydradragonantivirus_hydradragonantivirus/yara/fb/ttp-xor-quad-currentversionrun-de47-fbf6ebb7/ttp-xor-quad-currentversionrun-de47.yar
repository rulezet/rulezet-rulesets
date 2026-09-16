rule TTP_XOR_QUAD_CurrentVersionRun_de47 {
  strings:
    $key_de47 = { 8d 28 [2] a9 26 [2] 82 0a [2] ac 28 [2] b8 33 [2] b7 29 [2] a9 34 [2] ab 35 [2] b0 33 [2] ac 34 [2] b0 1b }

  condition:
    any of them
}
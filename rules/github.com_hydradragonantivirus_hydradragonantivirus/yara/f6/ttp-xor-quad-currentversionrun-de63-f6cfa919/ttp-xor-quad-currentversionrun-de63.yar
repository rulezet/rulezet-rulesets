rule TTP_XOR_QUAD_CurrentVersionRun_de63 {
  strings:
    $key_de63 = { 8d 0c [2] a9 02 [2] 82 2e [2] ac 0c [2] b8 17 [2] b7 0d [2] a9 10 [2] ab 11 [2] b0 17 [2] ac 10 [2] b0 3f }

  condition:
    any of them
}
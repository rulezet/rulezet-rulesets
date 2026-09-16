rule TTP_XOR_QUAD_CurrentVersionRun_de54 {
  strings:
    $key_de54 = { 8d 3b [2] a9 35 [2] 82 19 [2] ac 3b [2] b8 20 [2] b7 3a [2] a9 27 [2] ab 26 [2] b0 20 [2] ac 27 [2] b0 08 }

  condition:
    any of them
}
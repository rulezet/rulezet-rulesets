rule TTP_XOR_QUAD_CurrentVersionRun_de45 {
  strings:
    $key_de45 = { 8d 2a [2] a9 24 [2] 82 08 [2] ac 2a [2] b8 31 [2] b7 2b [2] a9 36 [2] ab 37 [2] b0 31 [2] ac 36 [2] b0 19 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_de48 {
  strings:
    $key_de48 = { 8d 27 [2] a9 29 [2] 82 05 [2] ac 27 [2] b8 3c [2] b7 26 [2] a9 3b [2] ab 3a [2] b0 3c [2] ac 3b [2] b0 14 }

  condition:
    any of them
}
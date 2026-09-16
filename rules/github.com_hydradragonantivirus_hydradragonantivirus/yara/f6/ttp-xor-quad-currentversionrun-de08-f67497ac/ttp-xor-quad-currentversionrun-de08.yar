rule TTP_XOR_QUAD_CurrentVersionRun_de08 {
  strings:
    $key_de08 = { 8d 67 [2] a9 69 [2] 82 45 [2] ac 67 [2] b8 7c [2] b7 66 [2] a9 7b [2] ab 7a [2] b0 7c [2] ac 7b [2] b0 54 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_de34 {
  strings:
    $key_de34 = { 8d 5b [2] a9 55 [2] 82 79 [2] ac 5b [2] b8 40 [2] b7 5a [2] a9 47 [2] ab 46 [2] b0 40 [2] ac 47 [2] b0 68 }

  condition:
    any of them
}
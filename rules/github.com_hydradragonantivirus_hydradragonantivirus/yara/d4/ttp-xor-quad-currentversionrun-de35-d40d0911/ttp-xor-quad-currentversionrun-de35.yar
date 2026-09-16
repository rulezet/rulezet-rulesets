rule TTP_XOR_QUAD_CurrentVersionRun_de35 {
  strings:
    $key_de35 = { 8d 5a [2] a9 54 [2] 82 78 [2] ac 5a [2] b8 41 [2] b7 5b [2] a9 46 [2] ab 47 [2] b0 41 [2] ac 46 [2] b0 69 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_de87 {
  strings:
    $key_de87 = { 8d e8 [2] a9 e6 [2] 82 ca [2] ac e8 [2] b8 f3 [2] b7 e9 [2] a9 f4 [2] ab f5 [2] b0 f3 [2] ac f4 [2] b0 db }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_c287 {
  strings:
    $key_c287 = { 91 e8 [2] b5 e6 [2] 9e ca [2] b0 e8 [2] a4 f3 [2] ab e9 [2] b5 f4 [2] b7 f5 [2] ac f3 [2] b0 f4 [2] ac db }

  condition:
    any of them
}
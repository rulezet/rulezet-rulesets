rule TTP_XOR_QUAD_CurrentVersionRun_c787 {
  strings:
    $key_c787 = { 94 e8 [2] b0 e6 [2] 9b ca [2] b5 e8 [2] a1 f3 [2] ae e9 [2] b0 f4 [2] b2 f5 [2] a9 f3 [2] b5 f4 [2] a9 db }

  condition:
    any of them
}
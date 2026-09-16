rule TTP_XOR_QUAD_CurrentVersionRun_c786 {
  strings:
    $key_c786 = { 94 e9 [2] b0 e7 [2] 9b cb [2] b5 e9 [2] a1 f2 [2] ae e8 [2] b0 f5 [2] b2 f4 [2] a9 f2 [2] b5 f5 [2] a9 da }

  condition:
    any of them
}
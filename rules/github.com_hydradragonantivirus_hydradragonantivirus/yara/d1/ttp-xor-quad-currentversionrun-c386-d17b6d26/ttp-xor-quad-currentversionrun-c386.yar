rule TTP_XOR_QUAD_CurrentVersionRun_c386 {
  strings:
    $key_c386 = { 90 e9 [2] b4 e7 [2] 9f cb [2] b1 e9 [2] a5 f2 [2] aa e8 [2] b4 f5 [2] b6 f4 [2] ad f2 [2] b1 f5 [2] ad da }

  condition:
    any of them
}
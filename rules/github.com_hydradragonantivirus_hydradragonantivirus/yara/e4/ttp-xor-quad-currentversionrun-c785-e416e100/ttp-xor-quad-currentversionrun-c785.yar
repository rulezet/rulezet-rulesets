rule TTP_XOR_QUAD_CurrentVersionRun_c785 {
  strings:
    $key_c785 = { 94 ea [2] b0 e4 [2] 9b c8 [2] b5 ea [2] a1 f1 [2] ae eb [2] b0 f6 [2] b2 f7 [2] a9 f1 [2] b5 f6 [2] a9 d9 }

  condition:
    any of them
}
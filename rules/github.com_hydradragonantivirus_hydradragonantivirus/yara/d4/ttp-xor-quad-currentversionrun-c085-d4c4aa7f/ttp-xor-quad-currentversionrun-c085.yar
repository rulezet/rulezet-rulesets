rule TTP_XOR_QUAD_CurrentVersionRun_c085 {
  strings:
    $key_c085 = { 93 ea [2] b7 e4 [2] 9c c8 [2] b2 ea [2] a6 f1 [2] a9 eb [2] b7 f6 [2] b5 f7 [2] ae f1 [2] b2 f6 [2] ae d9 }

  condition:
    any of them
}
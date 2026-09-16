rule TTP_XOR_QUAD_CurrentVersionRun_c799 {
  strings:
    $key_c799 = { 94 f6 [2] b0 f8 [2] 9b d4 [2] b5 f6 [2] a1 ed [2] ae f7 [2] b0 ea [2] b2 eb [2] a9 ed [2] b5 ea [2] a9 c5 }

  condition:
    any of them
}
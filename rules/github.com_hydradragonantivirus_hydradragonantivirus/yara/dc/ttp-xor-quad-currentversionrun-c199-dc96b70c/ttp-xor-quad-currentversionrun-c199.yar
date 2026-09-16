rule TTP_XOR_QUAD_CurrentVersionRun_c199 {
  strings:
    $key_c199 = { 92 f6 [2] b6 f8 [2] 9d d4 [2] b3 f6 [2] a7 ed [2] a8 f7 [2] b6 ea [2] b4 eb [2] af ed [2] b3 ea [2] af c5 }

  condition:
    any of them
}
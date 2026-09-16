rule TTP_XOR_QUAD_CurrentVersionRun_c599 {
  strings:
    $key_c599 = { 96 f6 [2] b2 f8 [2] 99 d4 [2] b7 f6 [2] a3 ed [2] ac f7 [2] b2 ea [2] b0 eb [2] ab ed [2] b7 ea [2] ab c5 }

  condition:
    any of them
}
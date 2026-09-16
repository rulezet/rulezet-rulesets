rule TTP_XOR_QUAD_CurrentVersionRun_d599 {
  strings:
    $key_d599 = { 86 f6 [2] a2 f8 [2] 89 d4 [2] a7 f6 [2] b3 ed [2] bc f7 [2] a2 ea [2] a0 eb [2] bb ed [2] a7 ea [2] bb c5 }

  condition:
    any of them
}
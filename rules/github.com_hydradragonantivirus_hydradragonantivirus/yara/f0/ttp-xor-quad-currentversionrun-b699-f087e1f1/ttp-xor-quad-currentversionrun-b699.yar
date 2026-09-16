rule TTP_XOR_QUAD_CurrentVersionRun_b699 {
  strings:
    $key_b699 = { e5 f6 [2] c1 f8 [2] ea d4 [2] c4 f6 [2] d0 ed [2] df f7 [2] c1 ea [2] c3 eb [2] d8 ed [2] c4 ea [2] d8 c5 }

  condition:
    any of them
}
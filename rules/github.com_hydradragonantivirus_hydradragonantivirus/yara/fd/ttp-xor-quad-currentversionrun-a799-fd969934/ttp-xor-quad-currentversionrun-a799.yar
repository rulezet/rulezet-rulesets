rule TTP_XOR_QUAD_CurrentVersionRun_a799 {
  strings:
    $key_a799 = { f4 f6 [2] d0 f8 [2] fb d4 [2] d5 f6 [2] c1 ed [2] ce f7 [2] d0 ea [2] d2 eb [2] c9 ed [2] d5 ea [2] c9 c5 }

  condition:
    any of them
}
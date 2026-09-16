rule TTP_XOR_QUAD_CurrentVersionRun_9499 {
  strings:
    $key_9499 = { c7 f6 [2] e3 f8 [2] c8 d4 [2] e6 f6 [2] f2 ed [2] fd f7 [2] e3 ea [2] e1 eb [2] fa ed [2] e6 ea [2] fa c5 }

  condition:
    any of them
}
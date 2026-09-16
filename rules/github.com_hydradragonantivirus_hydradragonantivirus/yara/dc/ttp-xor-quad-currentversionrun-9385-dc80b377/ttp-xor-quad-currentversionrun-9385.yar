rule TTP_XOR_QUAD_CurrentVersionRun_9385 {
  strings:
    $key_9385 = { c0 ea [2] e4 e4 [2] cf c8 [2] e1 ea [2] f5 f1 [2] fa eb [2] e4 f6 [2] e6 f7 [2] fd f1 [2] e1 f6 [2] fd d9 }

  condition:
    any of them
}
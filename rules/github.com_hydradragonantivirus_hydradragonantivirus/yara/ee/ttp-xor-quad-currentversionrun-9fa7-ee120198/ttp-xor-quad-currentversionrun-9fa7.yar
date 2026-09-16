rule TTP_XOR_QUAD_CurrentVersionRun_9fa7 {
  strings:
    $key_9fa7 = { cc c8 [2] e8 c6 [2] c3 ea [2] ed c8 [2] f9 d3 [2] f6 c9 [2] e8 d4 [2] ea d5 [2] f1 d3 [2] ed d4 [2] f1 fb }

  condition:
    any of them
}
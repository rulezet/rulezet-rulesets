rule TTP_XOR_QUAD_CurrentVersionRun_84d3 {
  strings:
    $key_84d3 = { d7 bc [2] f3 b2 [2] d8 9e [2] f6 bc [2] e2 a7 [2] ed bd [2] f3 a0 [2] f1 a1 [2] ea a7 [2] f6 a0 [2] ea 8f }

  condition:
    any of them
}
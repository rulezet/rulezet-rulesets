rule TTP_XOR_QUAD_CurrentVersionRun_9ad3 {
  strings:
    $key_9ad3 = { c9 bc [2] ed b2 [2] c6 9e [2] e8 bc [2] fc a7 [2] f3 bd [2] ed a0 [2] ef a1 [2] f4 a7 [2] e8 a0 [2] f4 8f }

  condition:
    any of them
}
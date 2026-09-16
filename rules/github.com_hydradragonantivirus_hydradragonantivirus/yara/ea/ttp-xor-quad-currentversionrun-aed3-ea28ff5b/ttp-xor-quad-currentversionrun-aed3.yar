rule TTP_XOR_QUAD_CurrentVersionRun_aed3 {
  strings:
    $key_aed3 = { fd bc [2] d9 b2 [2] f2 9e [2] dc bc [2] c8 a7 [2] c7 bd [2] d9 a0 [2] db a1 [2] c0 a7 [2] dc a0 [2] c0 8f }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_a9d3 {
  strings:
    $key_a9d3 = { fa bc [2] de b2 [2] f5 9e [2] db bc [2] cf a7 [2] c0 bd [2] de a0 [2] dc a1 [2] c7 a7 [2] db a0 [2] c7 8f }

  condition:
    any of them
}
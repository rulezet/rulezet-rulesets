rule TTP_XOR_QUAD_CurrentVersionRun_a8cf {
  strings:
    $key_a8cf = { fb a0 [2] df ae [2] f4 82 [2] da a0 [2] ce bb [2] c1 a1 [2] df bc [2] dd bd [2] c6 bb [2] da bc [2] c6 93 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_dccf {
  strings:
    $key_dccf = { 8f a0 [2] ab ae [2] 80 82 [2] ae a0 [2] ba bb [2] b5 a1 [2] ab bc [2] a9 bd [2] b2 bb [2] ae bc [2] b2 93 }

  condition:
    any of them
}
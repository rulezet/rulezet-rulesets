rule TTP_XOR_QUAD_CurrentVersionRun_c7cf {
  strings:
    $key_c7cf = { 94 a0 [2] b0 ae [2] 9b 82 [2] b5 a0 [2] a1 bb [2] ae a1 [2] b0 bc [2] b2 bd [2] a9 bb [2] b5 bc [2] a9 93 }

  condition:
    any of them
}
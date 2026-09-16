rule TTP_XOR_QUAD_CurrentVersionRun_c5cf {
  strings:
    $key_c5cf = { 96 a0 [2] b2 ae [2] 99 82 [2] b7 a0 [2] a3 bb [2] ac a1 [2] b2 bc [2] b0 bd [2] ab bb [2] b7 bc [2] ab 93 }

  condition:
    any of them
}
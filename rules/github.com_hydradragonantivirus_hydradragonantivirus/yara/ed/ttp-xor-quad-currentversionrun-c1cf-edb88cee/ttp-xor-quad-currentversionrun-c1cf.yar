rule TTP_XOR_QUAD_CurrentVersionRun_c1cf {
  strings:
    $key_c1cf = { 92 a0 [2] b6 ae [2] 9d 82 [2] b3 a0 [2] a7 bb [2] a8 a1 [2] b6 bc [2] b4 bd [2] af bb [2] b3 bc [2] af 93 }

  condition:
    any of them
}
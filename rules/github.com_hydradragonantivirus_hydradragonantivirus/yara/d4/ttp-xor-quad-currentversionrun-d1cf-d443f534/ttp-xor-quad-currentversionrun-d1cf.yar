rule TTP_XOR_QUAD_CurrentVersionRun_d1cf {
  strings:
    $key_d1cf = { 82 a0 [2] a6 ae [2] 8d 82 [2] a3 a0 [2] b7 bb [2] b8 a1 [2] a6 bc [2] a4 bd [2] bf bb [2] a3 bc [2] bf 93 }

  condition:
    any of them
}
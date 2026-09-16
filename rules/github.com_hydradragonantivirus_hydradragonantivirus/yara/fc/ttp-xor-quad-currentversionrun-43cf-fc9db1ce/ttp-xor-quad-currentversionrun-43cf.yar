rule TTP_XOR_QUAD_CurrentVersionRun_43cf {
  strings:
    $key_43cf = { 10 a0 [2] 34 ae [2] 1f 82 [2] 31 a0 [2] 25 bb [2] 2a a1 [2] 34 bc [2] 36 bd [2] 2d bb [2] 31 bc [2] 2d 93 }

  condition:
    any of them
}
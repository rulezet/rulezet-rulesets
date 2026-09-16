rule TTP_XOR_QUAD_CurrentVersionRun_5fcf {
  strings:
    $key_5fcf = { 0c a0 [2] 28 ae [2] 03 82 [2] 2d a0 [2] 39 bb [2] 36 a1 [2] 28 bc [2] 2a bd [2] 31 bb [2] 2d bc [2] 31 93 }

  condition:
    any of them
}
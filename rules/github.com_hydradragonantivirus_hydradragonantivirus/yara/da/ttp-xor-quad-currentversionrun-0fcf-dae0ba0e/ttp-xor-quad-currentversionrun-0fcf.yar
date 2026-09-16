rule TTP_XOR_QUAD_CurrentVersionRun_0fcf {
  strings:
    $key_0fcf = { 5c a0 [2] 78 ae [2] 53 82 [2] 7d a0 [2] 69 bb [2] 66 a1 [2] 78 bc [2] 7a bd [2] 61 bb [2] 7d bc [2] 61 93 }

  condition:
    any of them
}
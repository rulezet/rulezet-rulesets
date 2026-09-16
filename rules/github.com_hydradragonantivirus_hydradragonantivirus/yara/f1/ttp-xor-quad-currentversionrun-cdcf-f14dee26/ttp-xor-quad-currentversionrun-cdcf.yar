rule TTP_XOR_QUAD_CurrentVersionRun_cdcf {
  strings:
    $key_cdcf = { 9e a0 [2] ba ae [2] 91 82 [2] bf a0 [2] ab bb [2] a4 a1 [2] ba bc [2] b8 bd [2] a3 bb [2] bf bc [2] a3 93 }

  condition:
    any of them
}
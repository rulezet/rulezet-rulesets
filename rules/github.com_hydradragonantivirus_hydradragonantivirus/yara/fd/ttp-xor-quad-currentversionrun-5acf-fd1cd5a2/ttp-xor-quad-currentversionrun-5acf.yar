rule TTP_XOR_QUAD_CurrentVersionRun_5acf {
  strings:
    $key_5acf = { 09 a0 [2] 2d ae [2] 06 82 [2] 28 a0 [2] 3c bb [2] 33 a1 [2] 2d bc [2] 2f bd [2] 34 bb [2] 28 bc [2] 34 93 }

  condition:
    any of them
}
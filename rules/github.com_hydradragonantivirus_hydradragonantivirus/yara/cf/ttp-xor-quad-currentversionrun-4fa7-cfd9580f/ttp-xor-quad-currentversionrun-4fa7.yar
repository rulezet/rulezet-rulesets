rule TTP_XOR_QUAD_CurrentVersionRun_4fa7 {
  strings:
    $key_4fa7 = { 1c c8 [2] 38 c6 [2] 13 ea [2] 3d c8 [2] 29 d3 [2] 26 c9 [2] 38 d4 [2] 3a d5 [2] 21 d3 [2] 3d d4 [2] 21 fb }

  condition:
    any of them
}
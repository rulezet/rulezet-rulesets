rule TTP_XOR_QUAD_CurrentVersionRun_6ea7 {
  strings:
    $key_6ea7 = { 3d c8 [2] 19 c6 [2] 32 ea [2] 1c c8 [2] 08 d3 [2] 07 c9 [2] 19 d4 [2] 1b d5 [2] 00 d3 [2] 1c d4 [2] 00 fb }

  condition:
    any of them
}
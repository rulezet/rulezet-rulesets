rule TTP_XOR_QUAD_CurrentVersionRun_1da7 {
  strings:
    $key_1da7 = { 4e c8 [2] 6a c6 [2] 41 ea [2] 6f c8 [2] 7b d3 [2] 74 c9 [2] 6a d4 [2] 68 d5 [2] 73 d3 [2] 6f d4 [2] 73 fb }

  condition:
    any of them
}
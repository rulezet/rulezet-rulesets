rule TTP_XOR_QUAD_CurrentVersionRun_2fa7 {
  strings:
    $key_2fa7 = { 7c c8 [2] 58 c6 [2] 73 ea [2] 5d c8 [2] 49 d3 [2] 46 c9 [2] 58 d4 [2] 5a d5 [2] 41 d3 [2] 5d d4 [2] 41 fb }

  condition:
    any of them
}
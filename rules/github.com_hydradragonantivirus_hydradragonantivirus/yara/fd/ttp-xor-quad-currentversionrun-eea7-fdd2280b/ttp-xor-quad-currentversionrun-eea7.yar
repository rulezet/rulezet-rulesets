rule TTP_XOR_QUAD_CurrentVersionRun_eea7 {
  strings:
    $key_eea7 = { bd c8 [2] 99 c6 [2] b2 ea [2] 9c c8 [2] 88 d3 [2] 87 c9 [2] 99 d4 [2] 9b d5 [2] 80 d3 [2] 9c d4 [2] 80 fb }

  condition:
    any of them
}
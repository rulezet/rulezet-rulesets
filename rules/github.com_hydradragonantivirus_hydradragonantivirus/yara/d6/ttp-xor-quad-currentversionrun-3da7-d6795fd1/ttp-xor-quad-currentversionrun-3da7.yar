rule TTP_XOR_QUAD_CurrentVersionRun_3da7 {
  strings:
    $key_3da7 = { 6e c8 [2] 4a c6 [2] 61 ea [2] 4f c8 [2] 5b d3 [2] 54 c9 [2] 4a d4 [2] 48 d5 [2] 53 d3 [2] 4f d4 [2] 53 fb }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_32a7 {
  strings:
    $key_32a7 = { 61 c8 [2] 45 c6 [2] 6e ea [2] 40 c8 [2] 54 d3 [2] 5b c9 [2] 45 d4 [2] 47 d5 [2] 5c d3 [2] 40 d4 [2] 5c fb }

  condition:
    any of them
}
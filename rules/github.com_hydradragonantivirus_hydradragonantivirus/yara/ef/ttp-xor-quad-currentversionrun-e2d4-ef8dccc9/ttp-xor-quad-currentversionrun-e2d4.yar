rule TTP_XOR_QUAD_CurrentVersionRun_e2d4 {
  strings:
    $key_e2d4 = { b1 bb [2] 95 b5 [2] be 99 [2] 90 bb [2] 84 a0 [2] 8b ba [2] 95 a7 [2] 97 a6 [2] 8c a0 [2] 90 a7 [2] 8c 88 }

  condition:
    any of them
}
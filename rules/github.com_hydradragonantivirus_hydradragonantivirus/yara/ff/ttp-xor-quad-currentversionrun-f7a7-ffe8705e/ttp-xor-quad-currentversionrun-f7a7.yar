rule TTP_XOR_QUAD_CurrentVersionRun_f7a7 {
  strings:
    $key_f7a7 = { a4 c8 [2] 80 c6 [2] ab ea [2] 85 c8 [2] 91 d3 [2] 9e c9 [2] 80 d4 [2] 82 d5 [2] 99 d3 [2] 85 d4 [2] 99 fb }

  condition:
    any of them
}
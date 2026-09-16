rule TTP_XOR_QUAD_CurrentVersionRun_d647 {
  strings:
    $key_d647 = { 85 28 [2] a1 26 [2] 8a 0a [2] a4 28 [2] b0 33 [2] bf 29 [2] a1 34 [2] a3 35 [2] b8 33 [2] a4 34 [2] b8 1b }

  condition:
    any of them
}
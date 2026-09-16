rule TTP_XOR_QUAD_CurrentVersionRun_d646 {
  strings:
    $key_d646 = { 85 29 [2] a1 27 [2] 8a 0b [2] a4 29 [2] b0 32 [2] bf 28 [2] a1 35 [2] a3 34 [2] b8 32 [2] a4 35 [2] b8 1a }

  condition:
    any of them
}
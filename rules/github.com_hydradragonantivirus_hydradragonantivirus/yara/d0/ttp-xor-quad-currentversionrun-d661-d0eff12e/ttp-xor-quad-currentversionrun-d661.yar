rule TTP_XOR_QUAD_CurrentVersionRun_d661 {
  strings:
    $key_d661 = { 85 0e [2] a1 00 [2] 8a 2c [2] a4 0e [2] b0 15 [2] bf 0f [2] a1 12 [2] a3 13 [2] b8 15 [2] a4 12 [2] b8 3d }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_c361 {
  strings:
    $key_c361 = { 90 0e [2] b4 00 [2] 9f 2c [2] b1 0e [2] a5 15 [2] aa 0f [2] b4 12 [2] b6 13 [2] ad 15 [2] b1 12 [2] ad 3d }

  condition:
    any of them
}
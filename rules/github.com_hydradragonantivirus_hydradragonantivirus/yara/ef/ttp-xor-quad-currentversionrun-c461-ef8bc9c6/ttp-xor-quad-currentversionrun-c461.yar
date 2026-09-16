rule TTP_XOR_QUAD_CurrentVersionRun_c461 {
  strings:
    $key_c461 = { 97 0e [2] b3 00 [2] 98 2c [2] b6 0e [2] a2 15 [2] ad 0f [2] b3 12 [2] b1 13 [2] aa 15 [2] b6 12 [2] aa 3d }

  condition:
    any of them
}
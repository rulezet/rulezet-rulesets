rule TTP_XOR_QUAD_CurrentVersionRun_c642 {
  strings:
    $key_c642 = { 95 2d [2] b1 23 [2] 9a 0f [2] b4 2d [2] a0 36 [2] af 2c [2] b1 31 [2] b3 30 [2] a8 36 [2] b4 31 [2] a8 1e }

  condition:
    any of them
}
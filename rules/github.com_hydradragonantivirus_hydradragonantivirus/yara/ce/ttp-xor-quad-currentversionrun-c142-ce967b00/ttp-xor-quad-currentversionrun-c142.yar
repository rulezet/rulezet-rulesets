rule TTP_XOR_QUAD_CurrentVersionRun_c142 {
  strings:
    $key_c142 = { 92 2d [2] b6 23 [2] 9d 0f [2] b3 2d [2] a7 36 [2] a8 2c [2] b6 31 [2] b4 30 [2] af 36 [2] b3 31 [2] af 1e }

  condition:
    any of them
}
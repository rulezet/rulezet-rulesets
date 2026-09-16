rule TTP_XOR_QUAD_CurrentVersionRun_c042 {
  strings:
    $key_c042 = { 93 2d [2] b7 23 [2] 9c 0f [2] b2 2d [2] a6 36 [2] a9 2c [2] b7 31 [2] b5 30 [2] ae 36 [2] b2 31 [2] ae 1e }

  condition:
    any of them
}
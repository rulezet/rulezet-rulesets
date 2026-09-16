rule TTP_XOR_QUAD_CurrentVersionRun_c163 {
  strings:
    $key_c163 = { 92 0c [2] b6 02 [2] 9d 2e [2] b3 0c [2] a7 17 [2] a8 0d [2] b6 10 [2] b4 11 [2] af 17 [2] b3 10 [2] af 3f }

  condition:
    any of them
}
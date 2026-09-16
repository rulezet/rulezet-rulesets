rule TTP_XOR_QUAD_CurrentVersionRun_c153 {
  strings:
    $key_c153 = { 92 3c [2] b6 32 [2] 9d 1e [2] b3 3c [2] a7 27 [2] a8 3d [2] b6 20 [2] b4 21 [2] af 27 [2] b3 20 [2] af 0f }

  condition:
    any of them
}
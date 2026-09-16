rule TTP_XOR_QUAD_CurrentVersionRun_c653 {
  strings:
    $key_c653 = { 95 3c [2] b1 32 [2] 9a 1e [2] b4 3c [2] a0 27 [2] af 3d [2] b1 20 [2] b3 21 [2] a8 27 [2] b4 20 [2] a8 0f }

  condition:
    any of them
}
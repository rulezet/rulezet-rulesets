rule TTP_XOR_QUAD_CurrentVersionRun_c646 {
  strings:
    $key_c646 = { 95 29 [2] b1 27 [2] 9a 0b [2] b4 29 [2] a0 32 [2] af 28 [2] b1 35 [2] b3 34 [2] a8 32 [2] b4 35 [2] a8 1a }

  condition:
    any of them
}
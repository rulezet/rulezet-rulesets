rule TTP_XOR_QUAD_CurrentVersionRun_c6ec {
  strings:
    $key_c6ec = { 95 83 [2] b1 8d [2] 9a a1 [2] b4 83 [2] a0 98 [2] af 82 [2] b1 9f [2] b3 9e [2] a8 98 [2] b4 9f [2] a8 b0 }

  condition:
    any of them
}
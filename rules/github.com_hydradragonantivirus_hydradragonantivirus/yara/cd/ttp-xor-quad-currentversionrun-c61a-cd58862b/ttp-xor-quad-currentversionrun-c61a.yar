rule TTP_XOR_QUAD_CurrentVersionRun_c61a {
  strings:
    $key_c61a = { 95 75 [2] b1 7b [2] 9a 57 [2] b4 75 [2] a0 6e [2] af 74 [2] b1 69 [2] b3 68 [2] a8 6e [2] b4 69 [2] a8 46 }

  condition:
    any of them
}
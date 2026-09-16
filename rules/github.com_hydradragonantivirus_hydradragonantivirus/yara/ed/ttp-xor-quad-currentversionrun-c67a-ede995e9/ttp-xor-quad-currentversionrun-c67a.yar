rule TTP_XOR_QUAD_CurrentVersionRun_c67a {
  strings:
    $key_c67a = { 95 15 [2] b1 1b [2] 9a 37 [2] b4 15 [2] a0 0e [2] af 14 [2] b1 09 [2] b3 08 [2] a8 0e [2] b4 09 [2] a8 26 }

  condition:
    any of them
}
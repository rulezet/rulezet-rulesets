rule TTP_XOR_QUAD_CurrentVersionRun_c6ef {
  strings:
    $key_c6ef = { 95 80 [2] b1 8e [2] 9a a2 [2] b4 80 [2] a0 9b [2] af 81 [2] b1 9c [2] b3 9d [2] a8 9b [2] b4 9c [2] a8 b3 }

  condition:
    any of them
}
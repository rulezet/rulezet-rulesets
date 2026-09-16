rule TTP_XOR_QUAD_CurrentVersionRun_c1ef {
  strings:
    $key_c1ef = { 92 80 [2] b6 8e [2] 9d a2 [2] b3 80 [2] a7 9b [2] a8 81 [2] b6 9c [2] b4 9d [2] af 9b [2] b3 9c [2] af b3 }

  condition:
    any of them
}
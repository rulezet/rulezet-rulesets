rule TTP_XOR_QUAD_CurrentVersionRun_c601 {
  strings:
    $key_c601 = { 95 6e [2] b1 60 [2] 9a 4c [2] b4 6e [2] a0 75 [2] af 6f [2] b1 72 [2] b3 73 [2] a8 75 [2] b4 72 [2] a8 5d }

  condition:
    any of them
}
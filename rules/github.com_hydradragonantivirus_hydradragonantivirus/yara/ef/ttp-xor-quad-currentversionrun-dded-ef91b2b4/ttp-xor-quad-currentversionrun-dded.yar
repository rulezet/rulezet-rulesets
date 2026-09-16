rule TTP_XOR_QUAD_CurrentVersionRun_dded {
  strings:
    $key_dded = { 8e 82 [2] aa 8c [2] 81 a0 [2] af 82 [2] bb 99 [2] b4 83 [2] aa 9e [2] a8 9f [2] b3 99 [2] af 9e [2] b3 b1 }

  condition:
    any of them
}
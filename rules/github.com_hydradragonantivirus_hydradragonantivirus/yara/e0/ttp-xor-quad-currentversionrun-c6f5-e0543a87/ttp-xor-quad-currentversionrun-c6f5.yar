rule TTP_XOR_QUAD_CurrentVersionRun_c6f5 {
  strings:
    $key_c6f5 = { 95 9a [2] b1 94 [2] 9a b8 [2] b4 9a [2] a0 81 [2] af 9b [2] b1 86 [2] b3 87 [2] a8 81 [2] b4 86 [2] a8 a9 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_d7f4 {
  strings:
    $key_d7f4 = { 84 9b [2] a0 95 [2] 8b b9 [2] a5 9b [2] b1 80 [2] be 9a [2] a0 87 [2] a2 86 [2] b9 80 [2] a5 87 [2] b9 a8 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_d7e8 {
  strings:
    $key_d7e8 = { 84 87 [2] a0 89 [2] 8b a5 [2] a5 87 [2] b1 9c [2] be 86 [2] a0 9b [2] a2 9a [2] b9 9c [2] a5 9b [2] b9 b4 }

  condition:
    any of them
}
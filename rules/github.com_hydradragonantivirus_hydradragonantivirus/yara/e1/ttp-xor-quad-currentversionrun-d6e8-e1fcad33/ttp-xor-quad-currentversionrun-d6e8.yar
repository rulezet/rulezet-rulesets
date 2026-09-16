rule TTP_XOR_QUAD_CurrentVersionRun_d6e8 {
  strings:
    $key_d6e8 = { 85 87 [2] a1 89 [2] 8a a5 [2] a4 87 [2] b0 9c [2] bf 86 [2] a1 9b [2] a3 9a [2] b8 9c [2] a4 9b [2] b8 b4 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_c4f5 {
  strings:
    $key_c4f5 = { 97 9a [2] b3 94 [2] 98 b8 [2] b6 9a [2] a2 81 [2] ad 9b [2] b3 86 [2] b1 87 [2] aa 81 [2] b6 86 [2] aa a9 }

  condition:
    any of them
}
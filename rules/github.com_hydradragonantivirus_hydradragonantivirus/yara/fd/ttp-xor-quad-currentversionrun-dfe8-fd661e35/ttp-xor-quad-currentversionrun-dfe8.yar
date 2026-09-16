rule TTP_XOR_QUAD_CurrentVersionRun_dfe8 {
  strings:
    $key_dfe8 = { 8c 87 [2] a8 89 [2] 83 a5 [2] ad 87 [2] b9 9c [2] b6 86 [2] a8 9b [2] aa 9a [2] b1 9c [2] ad 9b [2] b1 b4 }

  condition:
    any of them
}
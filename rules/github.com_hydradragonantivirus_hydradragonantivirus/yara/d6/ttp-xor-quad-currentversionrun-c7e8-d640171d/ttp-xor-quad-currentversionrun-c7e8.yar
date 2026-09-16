rule TTP_XOR_QUAD_CurrentVersionRun_c7e8 {
  strings:
    $key_c7e8 = { 94 87 [2] b0 89 [2] 9b a5 [2] b5 87 [2] a1 9c [2] ae 86 [2] b0 9b [2] b2 9a [2] a9 9c [2] b5 9b [2] a9 b4 }

  condition:
    any of them
}
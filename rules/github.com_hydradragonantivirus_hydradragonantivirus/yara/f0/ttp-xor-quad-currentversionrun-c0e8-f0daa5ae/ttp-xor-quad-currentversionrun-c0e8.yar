rule TTP_XOR_QUAD_CurrentVersionRun_c0e8 {
  strings:
    $key_c0e8 = { 93 87 [2] b7 89 [2] 9c a5 [2] b2 87 [2] a6 9c [2] a9 86 [2] b7 9b [2] b5 9a [2] ae 9c [2] b2 9b [2] ae b4 }

  condition:
    any of them
}
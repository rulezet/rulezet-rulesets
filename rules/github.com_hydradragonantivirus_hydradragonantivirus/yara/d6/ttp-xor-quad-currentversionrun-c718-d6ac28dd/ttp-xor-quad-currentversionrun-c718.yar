rule TTP_XOR_QUAD_CurrentVersionRun_c718 {
  strings:
    $key_c718 = { 94 77 [2] b0 79 [2] 9b 55 [2] b5 77 [2] a1 6c [2] ae 76 [2] b0 6b [2] b2 6a [2] a9 6c [2] b5 6b [2] a9 44 }

  condition:
    any of them
}
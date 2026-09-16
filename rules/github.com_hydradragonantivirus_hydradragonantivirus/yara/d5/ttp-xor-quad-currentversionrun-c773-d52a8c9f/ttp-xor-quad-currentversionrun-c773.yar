rule TTP_XOR_QUAD_CurrentVersionRun_c773 {
  strings:
    $key_c773 = { 94 1c [2] b0 12 [2] 9b 3e [2] b5 1c [2] a1 07 [2] ae 1d [2] b0 00 [2] b2 01 [2] a9 07 [2] b5 00 [2] a9 2f }

  condition:
    any of them
}
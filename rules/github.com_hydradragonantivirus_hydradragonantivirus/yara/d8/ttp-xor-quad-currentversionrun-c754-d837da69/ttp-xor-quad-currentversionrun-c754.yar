rule TTP_XOR_QUAD_CurrentVersionRun_c754 {
  strings:
    $key_c754 = { 94 3b [2] b0 35 [2] 9b 19 [2] b5 3b [2] a1 20 [2] ae 3a [2] b0 27 [2] b2 26 [2] a9 20 [2] b5 27 [2] a9 08 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_c747 {
  strings:
    $key_c747 = { 94 28 [2] b0 26 [2] 9b 0a [2] b5 28 [2] a1 33 [2] ae 29 [2] b0 34 [2] b2 35 [2] a9 33 [2] b5 34 [2] a9 1b }

  condition:
    any of them
}
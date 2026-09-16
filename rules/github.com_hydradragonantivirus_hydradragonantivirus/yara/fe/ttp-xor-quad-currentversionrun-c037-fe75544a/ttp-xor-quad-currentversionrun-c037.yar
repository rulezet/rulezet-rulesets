rule TTP_XOR_QUAD_CurrentVersionRun_c037 {
  strings:
    $key_c037 = { 93 58 [2] b7 56 [2] 9c 7a [2] b2 58 [2] a6 43 [2] a9 59 [2] b7 44 [2] b5 45 [2] ae 43 [2] b2 44 [2] ae 6b }

  condition:
    any of them
}
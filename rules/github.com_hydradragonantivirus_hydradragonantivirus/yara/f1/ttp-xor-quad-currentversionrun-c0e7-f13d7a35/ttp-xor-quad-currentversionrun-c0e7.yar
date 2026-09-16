rule TTP_XOR_QUAD_CurrentVersionRun_c0e7 {
  strings:
    $key_c0e7 = { 93 88 [2] b7 86 [2] 9c aa [2] b2 88 [2] a6 93 [2] a9 89 [2] b7 94 [2] b5 95 [2] ae 93 [2] b2 94 [2] ae bb }

  condition:
    any of them
}
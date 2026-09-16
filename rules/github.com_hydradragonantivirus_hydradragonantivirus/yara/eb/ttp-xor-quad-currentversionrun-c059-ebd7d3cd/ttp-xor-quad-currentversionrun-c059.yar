rule TTP_XOR_QUAD_CurrentVersionRun_c059 {
  strings:
    $key_c059 = { 93 36 [2] b7 38 [2] 9c 14 [2] b2 36 [2] a6 2d [2] a9 37 [2] b7 2a [2] b5 2b [2] ae 2d [2] b2 2a [2] ae 05 }

  condition:
    any of them
}
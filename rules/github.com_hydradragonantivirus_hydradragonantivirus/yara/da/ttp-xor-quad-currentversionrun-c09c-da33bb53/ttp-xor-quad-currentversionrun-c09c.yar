rule TTP_XOR_QUAD_CurrentVersionRun_c09c {
  strings:
    $key_c09c = { 93 f3 [2] b7 fd [2] 9c d1 [2] b2 f3 [2] a6 e8 [2] a9 f2 [2] b7 ef [2] b5 ee [2] ae e8 [2] b2 ef [2] ae c0 }

  condition:
    any of them
}
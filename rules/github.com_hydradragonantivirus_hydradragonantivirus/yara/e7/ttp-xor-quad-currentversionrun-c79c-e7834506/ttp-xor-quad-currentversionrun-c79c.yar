rule TTP_XOR_QUAD_CurrentVersionRun_c79c {
  strings:
    $key_c79c = { 94 f3 [2] b0 fd [2] 9b d1 [2] b5 f3 [2] a1 e8 [2] ae f2 [2] b0 ef [2] b2 ee [2] a9 e8 [2] b5 ef [2] a9 c0 }

  condition:
    any of them
}
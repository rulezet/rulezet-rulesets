rule TTP_XOR_QUAD_CurrentVersionRun_c781 {
  strings:
    $key_c781 = { 94 ee [2] b0 e0 [2] 9b cc [2] b5 ee [2] a1 f5 [2] ae ef [2] b0 f2 [2] b2 f3 [2] a9 f5 [2] b5 f2 [2] a9 dd }

  condition:
    any of them
}
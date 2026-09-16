rule TTP_XOR_QUAD_CurrentVersionRun_c681 {
  strings:
    $key_c681 = { 95 ee [2] b1 e0 [2] 9a cc [2] b4 ee [2] a0 f5 [2] af ef [2] b1 f2 [2] b3 f3 [2] a8 f5 [2] b4 f2 [2] a8 dd }

  condition:
    any of them
}
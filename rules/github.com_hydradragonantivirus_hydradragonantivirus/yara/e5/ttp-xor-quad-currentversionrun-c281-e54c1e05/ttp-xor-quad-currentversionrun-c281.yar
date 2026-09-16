rule TTP_XOR_QUAD_CurrentVersionRun_c281 {
  strings:
    $key_c281 = { 91 ee [2] b5 e0 [2] 9e cc [2] b0 ee [2] a4 f5 [2] ab ef [2] b5 f2 [2] b7 f3 [2] ac f5 [2] b0 f2 [2] ac dd }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_0081 {
  strings:
    $key_0081 = { 53 ee [2] 77 e0 [2] 5c cc [2] 72 ee [2] 66 f5 [2] 69 ef [2] 77 f2 [2] 75 f3 [2] 6e f5 [2] 72 f2 [2] 6e dd }

  condition:
    any of them
}
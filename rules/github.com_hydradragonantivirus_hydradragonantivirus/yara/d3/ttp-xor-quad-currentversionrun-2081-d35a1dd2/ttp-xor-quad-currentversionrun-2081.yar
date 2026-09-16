rule TTP_XOR_QUAD_CurrentVersionRun_2081 {
  strings:
    $key_2081 = { 73 ee [2] 57 e0 [2] 7c cc [2] 52 ee [2] 46 f5 [2] 49 ef [2] 57 f2 [2] 55 f3 [2] 4e f5 [2] 52 f2 [2] 4e dd }

  condition:
    any of them
}
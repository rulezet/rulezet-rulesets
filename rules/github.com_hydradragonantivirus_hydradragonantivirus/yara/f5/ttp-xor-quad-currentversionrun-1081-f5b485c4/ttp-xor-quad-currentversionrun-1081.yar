rule TTP_XOR_QUAD_CurrentVersionRun_1081 {
  strings:
    $key_1081 = { 43 ee [2] 67 e0 [2] 4c cc [2] 62 ee [2] 76 f5 [2] 79 ef [2] 67 f2 [2] 65 f3 [2] 7e f5 [2] 62 f2 [2] 7e dd }

  condition:
    any of them
}
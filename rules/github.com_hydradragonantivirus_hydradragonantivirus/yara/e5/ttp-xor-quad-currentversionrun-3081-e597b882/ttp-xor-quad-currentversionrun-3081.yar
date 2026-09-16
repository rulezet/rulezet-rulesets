rule TTP_XOR_QUAD_CurrentVersionRun_3081 {
  strings:
    $key_3081 = { 63 ee [2] 47 e0 [2] 6c cc [2] 42 ee [2] 56 f5 [2] 59 ef [2] 47 f2 [2] 45 f3 [2] 5e f5 [2] 42 f2 [2] 5e dd }

  condition:
    any of them
}
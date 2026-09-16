rule TTP_XOR_QUAD_CurrentVersionRun_209b {
  strings:
    $key_209b = { 73 f4 [2] 57 fa [2] 7c d6 [2] 52 f4 [2] 46 ef [2] 49 f5 [2] 57 e8 [2] 55 e9 [2] 4e ef [2] 52 e8 [2] 4e c7 }

  condition:
    any of them
}
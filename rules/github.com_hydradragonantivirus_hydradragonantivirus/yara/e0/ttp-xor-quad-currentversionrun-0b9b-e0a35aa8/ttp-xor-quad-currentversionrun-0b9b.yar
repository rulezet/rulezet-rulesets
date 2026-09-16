rule TTP_XOR_QUAD_CurrentVersionRun_0b9b {
  strings:
    $key_0b9b = { 58 f4 [2] 7c fa [2] 57 d6 [2] 79 f4 [2] 6d ef [2] 62 f5 [2] 7c e8 [2] 7e e9 [2] 65 ef [2] 79 e8 [2] 65 c7 }

  condition:
    any of them
}
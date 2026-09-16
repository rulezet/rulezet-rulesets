rule TTP_XOR_QUAD_CurrentVersionRun_6b9b {
  strings:
    $key_6b9b = { 38 f4 [2] 1c fa [2] 37 d6 [2] 19 f4 [2] 0d ef [2] 02 f5 [2] 1c e8 [2] 1e e9 [2] 05 ef [2] 19 e8 [2] 05 c7 }

  condition:
    any of them
}
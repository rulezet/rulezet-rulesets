rule TTP_XOR_QUAD_CurrentVersionRun_529b {
  strings:
    $key_529b = { 01 f4 [2] 25 fa [2] 0e d6 [2] 20 f4 [2] 34 ef [2] 3b f5 [2] 25 e8 [2] 27 e9 [2] 3c ef [2] 20 e8 [2] 3c c7 }

  condition:
    any of them
}
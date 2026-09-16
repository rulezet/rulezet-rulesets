rule TTP_XOR_QUAD_CurrentVersionRun_029b {
  strings:
    $key_029b = { 51 f4 [2] 75 fa [2] 5e d6 [2] 70 f4 [2] 64 ef [2] 6b f5 [2] 75 e8 [2] 77 e9 [2] 6c ef [2] 70 e8 [2] 6c c7 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_229b {
  strings:
    $key_229b = { 71 f4 [2] 55 fa [2] 7e d6 [2] 50 f4 [2] 44 ef [2] 4b f5 [2] 55 e8 [2] 57 e9 [2] 4c ef [2] 50 e8 [2] 4c c7 }

  condition:
    any of them
}
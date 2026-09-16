rule TTP_XOR_QUAD_CurrentVersionRun_e29b {
  strings:
    $key_e29b = { b1 f4 [2] 95 fa [2] be d6 [2] 90 f4 [2] 84 ef [2] 8b f5 [2] 95 e8 [2] 97 e9 [2] 8c ef [2] 90 e8 [2] 8c c7 }

  condition:
    any of them
}
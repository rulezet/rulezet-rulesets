rule TTP_XOR_QUAD_CurrentVersionRun_489b {
  strings:
    $key_489b = { 1b f4 [2] 3f fa [2] 14 d6 [2] 3a f4 [2] 2e ef [2] 21 f5 [2] 3f e8 [2] 3d e9 [2] 26 ef [2] 3a e8 [2] 26 c7 }

  condition:
    any of them
}
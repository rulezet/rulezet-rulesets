rule TTP_XOR_QUAD_CurrentVersionRun_189b {
  strings:
    $key_189b = { 4b f4 [2] 6f fa [2] 44 d6 [2] 6a f4 [2] 7e ef [2] 71 f5 [2] 6f e8 [2] 6d e9 [2] 76 ef [2] 6a e8 [2] 76 c7 }

  condition:
    any of them
}